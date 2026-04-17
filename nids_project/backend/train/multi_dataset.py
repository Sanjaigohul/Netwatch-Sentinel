"""
backend/train/multi_dataset.py
─────────────────────────────────────────────────────────────────────────────
Combines N datasets into one balanced training matrix.

Pipeline
────────
  load_all()
    │
    ├─ per dataset: load → validate → log stats
    │
    ├─ merge:  np.vstack / np.concatenate
    │
    ├─ dedup:  remove near-duplicate rows (cosine distance < ε)
    │
    ├─ balance: SMOTE oversample minority classes
    │            + cap majority class (Normal) if too dominant
    │
    └─ shuffle + return (X, y)
"""

import logging
import numpy as np
from collections import Counter

from config import Config

logger = logging.getLogger(__name__)


# ── Public API ────────────────────────────────────────────────────────────────

def merge_datasets(datasets: list[tuple]) -> tuple[np.ndarray, np.ndarray]:
    """
    datasets : list of (X, y) tuples (already loaded by loaders)

    Returns
    -------
    X_merged : np.ndarray  shape (N, N_FEATURES)
    y_merged : np.ndarray  shape (N,)  string labels
    """
    if not datasets:
        raise ValueError("No datasets provided")

    Xs, ys = zip(*datasets)

    # ── 1. Stack ─────────────────────────────────────────────────────────────
    X = np.vstack(Xs).astype(np.float32)
    y = np.concatenate(ys)

    logger.info(f"Merged {len(datasets)} dataset(s): total {len(X)} rows")
    _log_class_dist(y, "Before balancing")

    # ── 2. Remove near-duplicates ─────────────────────────────────────────────
    X, y = _deduplicate(X, y, tol=1e-6)
    logger.info(f"After dedup: {len(X)} rows")

    # ── 3. Balance classes ────────────────────────────────────────────────────
    X, y = _balance(X, y)
    logger.info(f"After balancing: {len(X)} rows")
    _log_class_dist(y, "Final")

    # ── 4. Shuffle ────────────────────────────────────────────────────────────
    idx = np.random.default_rng(42).permutation(len(X))
    return X[idx], y[idx]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _log_class_dist(y: np.ndarray, label: str = ""):
    dist = Counter(y)
    parts = [f"{k}:{v}" for k, v in sorted(dist.items())]
    logger.info(f"  {label}: {', '.join(parts)}")


def _deduplicate(X: np.ndarray, y: np.ndarray,
                 tol: float = 1e-6) -> tuple:
    """
    Remove rows that are exactly (within tol) duplicated.
    Uses a rounded-view hash for efficiency — O(n) not O(n²).
    """
    # Round to 4 decimal places and hash each row
    rounded = np.round(X, 4)
    keys    = [tuple(row) for row in rounded]
    seen    = set()
    mask    = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            mask.append(True)
        else:
            mask.append(False)

    mask = np.array(mask)
    n_removed = (~mask).sum()
    if n_removed:
        logger.info(f"  Dedup removed {n_removed} duplicate rows")
    return X[mask], y[mask]


def _balance(X: np.ndarray, y: np.ndarray,
             normal_cap_ratio: float = 3.0,
             smote_min_samples: int = 50,
             min_class_samples: int = 5) -> tuple:
    """
    1. Cap 'Normal' class at  normal_cap_ratio × (second-largest class count)
    2. SMOTE oversample minority classes to median class size
       (falls back to random oversample if SMOTE unavailable)
    """
    counts = Counter(y)
    attack_counts = {k: v for k, v in counts.items() if k != "Normal"}

    if not attack_counts:
        logger.warning("No attack samples found – skipping balancing")
        return X, y

    # ── Cap Normal ────────────────────────────────────────────────────────────
    second_largest = sorted(attack_counts.values(), reverse=True)[0]
    cap = int(second_largest * normal_cap_ratio)

    if counts.get("Normal", 0) > cap:
        normal_idx = np.where(y == "Normal")[0]
        rng = np.random.default_rng(42)
        keep = rng.choice(normal_idx, size=cap, replace=False)
        other_idx = np.where(y != "Normal")[0]
        all_idx = np.concatenate([keep, other_idx])
        X, y = X[all_idx], y[all_idx]
        logger.info(f"  Normal class capped at {cap}")

    counts = Counter(y)

    # ── Ensure minimum per-class count ─────────────────────────────────────
    if min_class_samples > 1:
        X, y = _ensure_min_class_samples(X, y, min_class_samples)
        counts = Counter(y)

    # ── SMOTE oversample attack classes ──────────────────────────────────────
    target_n = int(np.median(list(counts.values())))
    target_n = max(target_n, smote_min_samples, min_class_samples)

    # Classes that need oversampling
    minority = {k: v for k, v in counts.items()
                if v < target_n and v >= 6}  # SMOTE needs k_neighbours samples

    if not minority:
        logger.info("  No minority classes need oversampling")
        return X, y

    try:
        from imblearn.over_sampling import SMOTE
        from sklearn.preprocessing import LabelEncoder

        le = LabelEncoder()
        y_enc = le.fit_transform(y)

        strategy = {le.transform([cls])[0]: target_n
                    for cls in minority
                    if len(np.where(y == cls)[0]) >= 6}

        # Clamp majority to avoid SMOTE crash
        for cls_int in np.unique(y_enc):
            cls_name = le.inverse_transform([cls_int])[0]
            if cls_name not in minority:
                strategy[cls_int] = int(counts[cls_name])

        sm   = SMOTE(sampling_strategy=strategy, k_neighbors=5,
                     random_state=42)
        X_r, y_r = sm.fit_resample(X, y_enc)
        y_r = le.inverse_transform(y_r)

        logger.info(f"  SMOTE oversampled {list(minority.keys())} → target {target_n}")
        return X_r.astype(np.float32), y_r

    except ImportError:
        logger.warning("  imbalanced-learn not installed – using random oversampling")
        return _random_oversample(X, y, target_n)
    except Exception as exc:
        logger.warning(f"  SMOTE failed ({exc}) – using random oversampling")
        return _random_oversample(X, y, target_n)


def _random_oversample(X: np.ndarray, y: np.ndarray,
                        target_n: int) -> tuple:
    """Simple random-with-replacement oversampling."""
    rng = np.random.default_rng(42)
    Xs, ys = [X], [y]
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        deficit = target_n - len(idx)
        if deficit > 0:
            extra = rng.choice(idx, size=deficit, replace=True)
            Xs.append(X[extra])
            ys.append(y[extra])
    X_out = np.vstack(Xs).astype(np.float32)
    y_out = np.concatenate(ys)
    shuf  = rng.permutation(len(X_out))
    return X_out[shuf], y_out[shuf]


def _ensure_min_class_samples(X: np.ndarray, y: np.ndarray,
                              min_count: int) -> tuple:
    """Randomly oversample classes with fewer than min_count samples."""
    rng = np.random.default_rng(42)
    Xs, ys = [X], [y]
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        deficit = min_count - len(idx)
        if deficit > 0:
            extra = rng.choice(idx, size=deficit, replace=True)
            Xs.append(X[extra])
            ys.append(y[extra])
            logger.info(f"  Class '{cls}' raised to {min_count} samples")
    X_out = np.vstack(Xs).astype(np.float32)
    y_out = np.concatenate(ys)
    shuf = rng.permutation(len(X_out))
    return X_out[shuf], y_out[shuf]
