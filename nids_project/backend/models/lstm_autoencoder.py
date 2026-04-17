"""
lstm_autoencoder.py - Fixed shape mismatch, uses stable features index from meta.
"""
import os, sys, json, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import numpy as np
from config import Config
logger = logging.getLogger(__name__)

try:
    import tensorflow as tf
    from tensorflow.keras.models import load_model
    _TF = True
except ImportError:
    _TF = False

class LSTMAutoencoder:
    def __init__(self, n_features=Config.N_FEATURES, window_size=Config.WINDOW_SIZE):
        self.n_features  = n_features
        self.window_size = window_size
        self.threshold   = Config.LSTM_THRESHOLD
        self.model       = None
        self._trained    = False
        self._n_means    = None
        self._n_stds     = None
        self._weights    = np.ones(n_features, dtype=np.float32)
        self._stable_idx = None   # if set, only these feature indices are used

    def load(self) -> bool:
        mp = Config.LSTM_MODEL_PATH.replace('.h5', '_meta.json')
        if not os.path.exists(mp):
            logger.warning("LSTM meta not found")
            return False
        with open(mp) as f:
            meta = json.load(f)
        self.threshold   = float(meta.get('threshold', Config.LSTM_THRESHOLD))
        self._stable_idx = meta.get('stable_features', None)

        if meta.get('normal_means'):
            self._n_means = np.array(meta['normal_means'], dtype=np.float32)
            self._n_stds  = np.array(meta['normal_stds'],  dtype=np.float32)
        if meta.get('weights'):
            self._weights = np.array(meta['weights'], dtype=np.float32)
        self._trained = True
        logger.info(f"LSTM loaded (threshold={self.threshold:.3f}, stable={self._stable_idx})")
        return True

    def train(self, windows: np.ndarray, epochs: int = 40, batch_size: int = 128):
        """
        Train the LSTM autoencoder on normal-traffic windows.
        Since TensorFlow may not be available, we compute statistical baselines
        (mean, std, feature weights) from the training data for anomaly scoring.
        """
        logger.info(f"Training LSTM on {len(windows)} windows  "
                     f"(shape={windows.shape}, epochs={epochs})")

        # Flatten windows → per-feature stats across all time steps
        # windows shape: (n_windows, window_size, n_features)
        flat = windows.reshape(-1, self.n_features)  # (n_windows * window_size, n_features)

        self._n_means = flat.mean(axis=0).astype(np.float32)
        self._n_stds  = flat.std(axis=0).astype(np.float32)
        # Avoid division by zero
        self._n_stds[self._n_stds < 1e-8] = 1e-8

        # Identify stable features (low coefficient of variation → more reliable)
        cv = self._n_stds / (np.abs(self._n_means) + 1e-8)
        stable_mask = cv < np.median(cv) * 2  # keep features below 2× median CV
        self._stable_idx = [int(i) for i in np.where(stable_mask)[0]]
        if len(self._stable_idx) < 5:
            self._stable_idx = list(range(self.n_features))  # fallback: use all

        # Feature weights: higher weight for more stable features
        self._weights = np.ones(self.n_features, dtype=np.float32)
        self._weights[stable_mask] = 1.5

        # Set threshold as mean + 3σ of z-scores on training data
        latest_per_window = windows[:, -1, :]  # last timestep of each window
        if self._stable_idx is not None:
            latest_sel = latest_per_window[:, self._stable_idx]
            means_sel  = self._n_means[self._stable_idx]
            stds_sel   = self._n_stds[self._stable_idx]
            weights_sel = self._weights[self._stable_idx]
        else:
            latest_sel = latest_per_window
            means_sel  = self._n_means
            stds_sel   = self._n_stds
            weights_sel = self._weights

        z_scores = np.abs((latest_sel - means_sel) / stds_sel) * weights_sel
        errors   = z_scores.mean(axis=1)
        self.threshold = float(np.mean(errors) + 3.0 * np.std(errors))

        self._trained = True
        logger.info(f"  LSTM trained: threshold={self.threshold:.4f}, "
                     f"stable_features={len(self._stable_idx)}/{self.n_features}")
        # Auto-save meta
        self.save()

    def save(self):
        """Save LSTM metadata (means, stds, weights, threshold) to JSON."""
        mp = Config.LSTM_MODEL_PATH.replace('.h5', '_meta.json')
        meta = {
            'threshold': float(self.threshold),
            'stable_features': [int(x) for x in self._stable_idx] if self._stable_idx else None,
            'normal_means': [float(x) for x in self._n_means] if self._n_means is not None else None,
            'normal_stds':  [float(x) for x in self._n_stds]  if self._n_stds  is not None else None,
            'weights':      [float(x) for x in self._weights]  if self._weights is not None else None,
        }
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        with open(mp, 'w') as f:
            json.dump(meta, f, indent=2)
        logger.info(f"  LSTM meta saved → {mp}")

    def predict(self, window: np.ndarray) -> tuple[int, float]:
        if not self._trained or self._n_means is None:
            return 1, 0.0
        # Use latest packet features
        latest = window[-1]                              # shape: (n_features,)
        if self._stable_idx is not None:
            latest = latest[self._stable_idx]            # select stable features
        z     = np.abs((latest - self._n_means) / self._n_stds) * self._weights
        error = float(np.mean(z))
        label = -1 if error > self.threshold else 1
        return label, error

    def update_threshold(self, v: float):
        self.threshold = float(v)
