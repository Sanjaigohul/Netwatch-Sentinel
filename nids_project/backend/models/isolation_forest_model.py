"""
isolation_forest_model.py
Uses stable per-packet features (not rate-based) for reliable detection.
"""
import os, sys, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import numpy as np, joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from config import Config

logger = logging.getLogger(__name__)

# Stable features: not affected by flow rate history
# [proto_tcp, proto_udp, proto_icmp, dst_port, wellknown, pkt_size, flags]
STABLE_IDX = [0, 1, 2, 4, 5, 6, 13]

class IsolationForestModel:
    def __init__(self):
        self.model:        IsolationForest | None = None
        self.scaler:       StandardScaler  | None = None
        self._offset:      float = -0.5
        self._stable_idx:  list  = STABLE_IDX

    def _extract_stable(self, fvec: np.ndarray) -> np.ndarray:
        return fvec[self._stable_idx].reshape(1, -1)

    def train(self, X_normal: np.ndarray):
        logger.info(f"Training IF on {len(X_normal)} samples (stable features)")
        X_stab = X_normal[:, self._stable_idx]
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X_stab)
        self.model = IsolationForest(n_estimators=100, contamination=0.02,
                                     max_samples='auto', random_state=42, n_jobs=1)
        self.model.fit(Xs)
        self._offset = float(self.model.offset_)
        logger.info(f"IF trained. offset_={self._offset:.4f}")

    def save(self):
        os.makedirs(Config.MODEL_DIR, exist_ok=True)
        joblib.dump(self.model,  Config.IF_MODEL_PATH)
        joblib.dump(self.scaler, Config.SCALER_PATH)
        joblib.dump({'offset': self._offset, 'stable_features': self._stable_idx},
                    Config.IF_MODEL_PATH.replace('.joblib', '_meta.joblib'))

    def load(self) -> bool:
        try:
            self.model  = joblib.load(Config.IF_MODEL_PATH)
            self.scaler = joblib.load(Config.SCALER_PATH)
            mp = Config.IF_MODEL_PATH.replace('.joblib', '_meta.joblib')
            if os.path.exists(mp):
                m = joblib.load(mp)
                self._offset      = m.get('offset', float(self.model.offset_))
                self._stable_idx  = m.get('stable_features', STABLE_IDX)
            else:
                self._offset = float(self.model.offset_)
            logger.info(f"IF loaded. offset_={self._offset:.4f}")
            return True
        except FileNotFoundError:
            logger.warning("IF model not found — using heuristic")
            return False

    def predict(self, fvec: np.ndarray) -> tuple[int, float]:
        if self.model is None or self.scaler is None:
            return self._heuristic(fvec)
        x    = fvec[self._stable_idx].reshape(1, -1)
        xs   = self.scaler.transform(x)
        lbl  = int(self.model.predict(xs)[0])
        raw  = float(self.model.score_samples(xs)[0])
        # Anomaly score: high when raw << offset_ (anomalous)
        span  = max(abs(self._offset) * 0.5, 0.1)
        score = float(np.clip((self._offset - raw) / span, 0.0, 1.0))
        return lbl, score

    @staticmethod
    def _heuristic(fvec: np.ndarray) -> tuple[int, float]:
        size_bytes = int(fvec[6] * 65535)
        udp        = fvec[1]
        flags      = fvec[13]
        score = 0.0
        if size_bytes < 50:   score += 0.6
        if udp > 0.5 and size_bytes > 600: score += 0.5
        score = float(np.clip(score, 0, 1))
        return (-1 if score > 0.4 else 1), score
