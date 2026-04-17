"""
backend/train/train_all.py – Multi-dataset training orchestrator.

Usage
─────
  # Synthetic only (no datasets needed):
  python backend/train/train_all.py

  # One real dataset:
  python backend/train/train_all.py --datasets cicids2017:/data/CICIDS2017

  # Multiple datasets:
  python backend/train/train_all.py \\
      --datasets cicids2017:/data/CIC,nslkdd:/data/NSL,unswnb15:/data/UNSW

  # Auto-detect type:
  python backend/train/train_all.py --datasets auto:/data/my_data.csv

Dataset type keys
─────────────────
  cicids2017, nslkdd, unswnb15, cicddos2019, kddcup99, custom, auto
"""

import os, sys, time, logging, argparse
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import Config
from backend.train.dataset_loaders import DATASET_LOADERS, auto_detect_dataset
from backend.train.multi_dataset   import merge_datasets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train")


# ─────────────────────────────────────────────────────────────────────────────
#  Synthetic generators
# ─────────────────────────────────────────────────────────────────────────────

def _make_normal(n: int = 5000) -> np.ndarray:
    rng = np.random.default_rng(42)
    X = np.zeros((n, Config.N_FEATURES), dtype=np.float32)
    protos = rng.choice([0, 1, 2], size=n, p=[0.80, 0.15, 0.05])
    X[:, 0] = (protos == 0).astype(np.float32)
    X[:, 1] = (protos == 1).astype(np.float32)
    X[:, 2] = (protos == 2).astype(np.float32)
    X[:, 3] = rng.uniform(0.01, 0.99, n)
    X[:, 4] = rng.choice([80/65535, 443/65535, 53/65535, 22/65535,
                           8080/65535, 3306/65535], size=n)
    X[:, 5] = rng.choice([0, 1], size=n, p=[0.3, 0.7])
    X[:, 6] = rng.beta(2, 5, n)
    X[:, 7] = rng.exponential(0.02, n).clip(0, 0.15)
    X[:, 8] = rng.exponential(0.03, n).clip(0, 0.2)
    X[:, 9] = rng.uniform(0, 0.1, n)
    X[:,10] = rng.uniform(0, 0.05, n)
    X[:,11] = rng.beta(3, 2, n)
    X[:,12] = rng.exponential(0.01, n).clip(0, 0.1)
    X[:,13] = rng.choice([0, 2/64, 16/64, 18/64, 24/64], size=n)
    X[:,14] = rng.exponential(0.01, n).clip(0, 0.05)
    X[:,15] = rng.exponential(0.01, n).clip(0, 0.1)
    X[:,16] = rng.exponential(0.001, n).clip(0, 0.01)
    return X


def _make_attack(attack_type: str, n: int = 1000) -> np.ndarray:
    rng = np.random.default_rng(hash(attack_type) % (2**31))
    X = np.zeros((n, Config.N_FEATURES), dtype=np.float32)
    if attack_type == "DoS":
        X[:, 0]=1.; X[:, 4]=80/65535; X[:, 5]=1.
        X[:, 6]=rng.uniform(0.001,0.002,n); X[:, 7]=rng.uniform(0.6,1.,n)
        X[:, 8]=rng.uniform(0.5,1.,n); X[:,13]=2/64
    elif attack_type == "DDoS":
        X[:, 1]=1.; X[:, 4]=53/65535
        X[:, 6]=rng.uniform(0.008,0.023,n)
        X[:, 7]=rng.uniform(0.6,1.,n); X[:, 8]=rng.uniform(0.5,1.,n)
    elif attack_type == "PortScan":
        X[:, 0]=1.; X[:, 4]=rng.uniform(0,1,n); X[:, 6]=44/65535
        X[:, 7]=rng.uniform(0.2,0.5,n); X[:,13]=2/64
        X[:,16]=rng.uniform(0.3,1.,n)
    elif attack_type == "BruteForce":
        X[:, 0]=1.; X[:, 4]=22/65535; X[:, 5]=1.
        X[:, 6]=rng.uniform(0.002,0.005,n)
        X[:, 7]=rng.uniform(0.15,0.4,n); X[:,13]=24/64
    elif attack_type == "Botnet":
        X[:, 0]=rng.choice([0.,1.],size=n,p=[0.5,0.5])
        X[:, 4]=rng.choice([80/65535,443/65535,6667/65535],size=n)
        X[:, 7]=rng.uniform(0.01,0.15,n); X[:, 8]=rng.uniform(0.02,0.2,n)
        X[:,16]=rng.uniform(0.05,0.3,n)
    elif attack_type == "WebAttack":
        X[:, 0]=1.
        X[:, 4]=rng.choice([80/65535,443/65535,8080/65535],size=n)
        X[:, 5]=1.; X[:, 6]=rng.uniform(0.01,0.02,n)
        X[:, 7]=rng.uniform(0.05,0.2,n); X[:,13]=24/64
    return X.astype(np.float32)


def generate_synthetic(n_normal: int = 5000, n_per_attack: int = 1000) -> tuple:
    logger.info(f"Generating synthetic data  (normal={n_normal}, per_attack={n_per_attack}) …")
    Xs = [_make_normal(n_normal)]
    ys = [np.full(n_normal, "Normal")]
    for at in Config.ATTACK_CLASSES[1:]:
        Xs.append(_make_attack(at, n_per_attack))
        ys.append(np.full(n_per_attack, at))
    X = np.vstack(Xs).astype(np.float32)
    y = np.concatenate(ys)
    logger.info(f"  Synthetic: {X.shape[0]} rows, {len(Config.ATTACK_CLASSES)} classes")
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
#  Dataset loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_one(dtype: str, path: str, max_rows: int) -> tuple | None:
    if dtype == "auto":
        dtype = auto_detect_dataset(path)
        logger.info(f"  Auto-detected type: {dtype}")
    loader = DATASET_LOADERS.get(dtype)
    if loader is None:
        logger.error(f"Unknown dataset type '{dtype}'. Valid: {list(DATASET_LOADERS.keys())}")
        return None
    try:
        t0 = time.time()
        X, y = loader(path, max_rows=max_rows)
        logger.info(f"  ✓ Loaded {dtype} in {time.time()-t0:.1f}s  shape={X.shape}")
        return X, y
    except FileNotFoundError as e:
        logger.error(f"  ✗ Not found: {e}")
        return None
    except Exception as e:
        logger.error(f"  ✗ {dtype}:{path} → {e}")
        return None


def load_all_datasets(specs: list[tuple[str,str]],
                      include_synthetic: bool = True,
                      max_rows: int = 150_000) -> tuple:
    loaded = []
    for i,(dtype,path) in enumerate(specs, 1):
        logger.info(f"[{i}/{len(specs)}] Loading {dtype}: {path}")
        r = _load_one(dtype, path, max_rows)
        if r is not None:
            loaded.append(r)

    if include_synthetic or not loaded:
        real_n   = sum(len(y) for _,y in loaded) if loaded else 0
        n_norm   = max(5000, real_n // 3) if real_n else 5000
        n_atk    = max(800,  n_norm // 7)
        loaded.append(generate_synthetic(n_norm, n_atk))

    if not loaded:
        logger.warning("All datasets failed – using synthetic only")
        loaded.append(generate_synthetic())

    logger.info("=" * 55)
    logger.info("Merging & balancing …")
    X, y = merge_datasets(loaded)
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
#  LSTM window builder
# ─────────────────────────────────────────────────────────────────────────────

def build_lstm_windows(X_normal: np.ndarray,
                       window_size: int = Config.WINDOW_SIZE,
                       max_windows: int = 15_000) -> np.ndarray:
    n = len(X_normal)
    if n < window_size:
        logger.warning(f"Only {n} normal samples (need ≥ {window_size}) – skipping LSTM")
        return np.array([], dtype=np.float32)
    wins = np.stack([X_normal[i:i+window_size] for i in range(n-window_size+1)])
    if len(wins) > max_windows:
        idx  = np.random.default_rng(42).choice(len(wins), max_windows, replace=False)
        wins = wins[idx]
    logger.info(f"  LSTM windows: {wins.shape}")
    return wins.astype(np.float32)


# ─────────────────────────────────────────────────────────────────────────────
#  Master training function
# ─────────────────────────────────────────────────────────────────────────────

def train_all(dataset_specs: list | None = None,
              include_synthetic: bool = True,
              max_rows_per_ds: int = 150_000,
              use_xgb: bool = False) -> dict:
    """
    Train all three models. Returns dict with model objects + metrics.

    dataset_specs : list of (dtype_str, path_str) pairs or None for synthetic only
    """
    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    specs = dataset_specs or []
    if not specs:
        include_synthetic = True

    # ── 1. Data ───────────────────────────────────────────────────────────────
    logger.info("=" * 55)
    logger.info("STEP 1/3 — Data Loading & Merging")
    logger.info("=" * 55)
    X_all, y_all = load_all_datasets(specs, include_synthetic, max_rows_per_ds)
    X_normal = X_all[y_all == "Normal"]
    logger.info(f"  Total: {len(X_all):,}  Normal: {len(X_normal):,}  "
                f"Attack: {len(X_all)-len(X_normal):,}")

    # ── 2. Isolation Forest ───────────────────────────────────────────────────
    logger.info("=" * 55)
    logger.info("STEP 2/3 — Isolation Forest")
    logger.info("=" * 55)
    from backend.models.isolation_forest_model import IsolationForestModel
    if_model = IsolationForestModel()
    if_model.train(X_normal)
    if_model.save()
    # Eval
    n_eval = min(500, len(X_normal))
    a_eval = min(500, (y_all != "Normal").sum())
    tnr = sum(if_model.predict(x)[0]==1  for x in X_normal[:n_eval]) / n_eval
    tpr = sum(if_model.predict(x)[0]==-1 for x in X_all[y_all!="Normal"][:a_eval]) / a_eval
    logger.info(f"  True-Normal-Rate={tnr:.3f}   True-Anomaly-Rate={tpr:.3f}")

    # ── 3. LSTM Autoencoder ───────────────────────────────────────────────────
    logger.info("=" * 55)
    logger.info("STEP 3a/3 — LSTM Autoencoder")
    logger.info("=" * 55)
    from backend.models.lstm_autoencoder import LSTMAutoencoder
    lstm = LSTMAutoencoder(n_features=Config.N_FEATURES, window_size=Config.WINDOW_SIZE)
    wins = build_lstm_windows(X_normal)
    if len(wins) >= 10:
        try:
            lstm.train(wins, epochs=40, batch_size=128)
            lstm.save()
        except RuntimeError as e:
            logger.warning(f"  LSTM skipped: {e}")
    else:
        logger.warning("  Skipping LSTM – not enough normal samples")

    # ── 4. Attack Classifier ──────────────────────────────────────────────────
    logger.info("=" * 55)
    logger.info("STEP 3b/3 — Attack Classifier")
    logger.info("=" * 55)
    from backend.models.attack_classifier import AttackClassifier
    clf = AttackClassifier()
    metrics = clf.train(X_all, y_all, use_xgb=use_xgb)
    clf.save()

    logger.info("=" * 55)
    logger.info("ALL MODELS TRAINED ✓")
    logger.info(f"  Classifier  Accuracy = {metrics['accuracy']:.4f}")
    logger.info(f"  Classifier  CV-F1    = {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")
    logger.info(f"  Models saved → {Config.MODEL_DIR}")
    logger.info("=" * 55)

    return {"isolation_forest": if_model, "lstm": lstm,
            "classifier": clf, "metrics": metrics,
            "n_samples": len(X_all), "n_normal": len(X_normal)}


# ─────────────────────────────────────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="NIDS multi-dataset trainer",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument("--datasets", type=str, default="",
                    help="Comma-separated type:path pairs  e.g. cicids2017:/data/CIC,nslkdd:/data/NSL")
    ap.add_argument("--synthetic",    action="store_true", help="Force include synthetic data")
    ap.add_argument("--no-synthetic", action="store_true", help="Skip synthetic (real datasets only)")
    ap.add_argument("--max-rows",     type=int, default=150_000, help="Row limit per dataset (default 150000)")
    ap.add_argument("--xgb",          action="store_true", help="Use XGBoost classifier")
    args = ap.parse_args()

    specs: list[tuple[str,str]] = []
    for token in args.datasets.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            dtype, path = token.split(":", 1)
            specs.append((dtype.strip().lower(), path.strip()))
        else:
            specs.append(("auto", token))

    inc_syn = True
    if args.no_synthetic and specs:
        inc_syn = False
    if args.synthetic:
        inc_syn = True

    train_all(dataset_specs=specs, include_synthetic=inc_syn,
              max_rows_per_ds=args.max_rows, use_xgb=args.xgb)
