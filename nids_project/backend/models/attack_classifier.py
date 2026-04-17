"""
models/attack_classifier.py – Fast version
Random Forest with 20 trees for <2ms inference.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import logging, numpy as np, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report, accuracy_score
from config import Config

logger = logging.getLogger(__name__)


class AttackClassifier:
    def __init__(self):
        self.model:   RandomForestClassifier | None = None
        self.encoder: LabelEncoder | None = None
        self.scaler:  StandardScaler | None = None
        self.classes: list[str] = Config.ATTACK_CLASSES

    def train(self, X: np.ndarray, y: np.ndarray, use_xgb: bool = False) -> dict:
        logger.info(f"Training attack classifier on {len(X)} samples …")
        self.encoder = LabelEncoder()
        y_enc = self.encoder.fit_transform(y)
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)

        if use_xgb:
            try:
                from xgboost import XGBClassifier
                self.model = XGBClassifier(
                    n_estimators=50, max_depth=6, learning_rate=0.15,
                    subsample=0.8, eval_metric="mlogloss",
                    random_state=42, n_jobs=1,
                )
                logger.info("Using XGBoost classifier")
            except ImportError:
                use_xgb = False

        if not use_xgb:
            self.model = RandomForestClassifier(
                n_estimators=20,       # fast: ~1.5ms inference
                max_depth=12,
                min_samples_split=5,
                class_weight="balanced",
                random_state=42,
                n_jobs=1,
            )

        self.model.fit(Xs, y_enc)
        min_class = int(np.min(np.bincount(y_enc))) if len(y_enc) else 0
        cv_f1_mean = float("nan")
        cv_f1_std = float("nan")
        if min_class >= 2:
            cv_folds = min(5, min_class)
            cv = cross_val_score(self.model, Xs, y_enc, cv=cv_folds,
                                 scoring="f1_macro", n_jobs=-1)
            cv_f1_mean = float(cv.mean())
            cv_f1_std = float(cv.std())
        else:
            logger.warning("Skipping CV: not enough samples per class")

        y_pred = self.model.predict(Xs)
        report = classification_report(y_enc, y_pred,
                                       target_names=self.encoder.classes_,
                                       output_dict=True)
        metrics = {
            "accuracy":   accuracy_score(y_enc, y_pred),
            "cv_f1_mean": cv_f1_mean,
            "cv_f1_std":  cv_f1_std,
            "report":     report,
        }
        logger.info(f"Classifier accuracy={metrics['accuracy']:.4f}  CV-F1={metrics['cv_f1_mean']:.4f}")
        return metrics

    def save(self):
        os.makedirs(Config.MODEL_DIR, exist_ok=True)
        joblib.dump(self.model,   Config.CLASSIFIER_PATH)
        joblib.dump(self.encoder, Config.LABEL_ENC_PATH)
        sp = Config.CLASSIFIER_PATH.replace(".joblib","_scaler.joblib")
        joblib.dump(self.scaler, sp)

    def load(self) -> bool:
        try:
            self.model   = joblib.load(Config.CLASSIFIER_PATH)
            self.encoder = joblib.load(Config.LABEL_ENC_PATH)
            sp = Config.CLASSIFIER_PATH.replace(".joblib","_scaler.joblib")
            if os.path.exists(sp):
                self.scaler = joblib.load(sp)
            logger.info("Attack classifier loaded")
            return True
        except FileNotFoundError:
            logger.warning("Classifier not found – using rule-based fallback")
            return False

    def predict(self, fvec: np.ndarray) -> tuple[str, float]:
        if self.model is None or self.encoder is None:
            return self._rule_based(fvec)
        x = fvec.reshape(1,-1)
        if self.scaler is not None:
            x = self.scaler.transform(x)
        pred  = int(self.model.predict(x)[0])
        proba = self.model.predict_proba(x)[0]
        conf  = float(np.max(proba))
        label = str(self.encoder.inverse_transform([pred])[0])
        return label, conf

    @staticmethod
    def _rule_based(fvec: np.ndarray) -> tuple[str, float]:
        pkt_rate = fvec[7]; byte_rate = fvec[8]
        dst_port = int(fvec[4]*65535); udst = fvec[16]
        p_icmp   = fvec[2]
        if pkt_rate > 0.6 and p_icmp: return "DoS", 0.75
        if pkt_rate > 0.7 and byte_rate > 0.5: return "DDoS", 0.72
        if udst > 0.05: return "PortScan", 0.70
        if dst_port == 22 and pkt_rate > 0.2: return "BruteForce", 0.68
        if dst_port in (80,443,8080) and byte_rate > 0.3: return "WebAttack", 0.65
        return "DoS", 0.55
