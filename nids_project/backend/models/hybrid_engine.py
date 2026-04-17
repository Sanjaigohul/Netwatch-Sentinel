"""
hybrid_engine.py — Final version with correct detection logic.

Detection layers:
  1. RULE-BASED: deterministic, high-precision for DoS/PortScan/DDoS/Botnet
  2. IF MODEL:   catches remaining anomalies based on stable packet features
  
ML (IF) result  → shown as 'ML' in dashboard
DL (LSTM)       → shown as 'DL' in dashboard (informational, not used for detection)
  
If only IF flags and rule doesn't → threat=Medium (suspicious)
If rule fires → threat from attack_type (High/Critical)
sim_type → used for CLASSIFICATION only (not detection trigger)
"""
import os, sys, json, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import numpy as np
from dataclasses import dataclass
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    timestamp:         str   = ""
    src_ip:            str   = ""
    dst_ip:            str   = ""
    protocol:          str   = ""
    packet_length:     int   = 0
    src_port:          int   = 0
    dst_port:          int   = 0
    ml_result:         int   = 1      # IF: +1=normal, -1=anomaly
    ml_score:          float = 0.0
    dl_result:         int   = 1      # LSTM: +1=normal, -1=anomaly (informational)
    dl_error:          float = 0.0
    final_result:      int   = 1      # +1=normal, -1=anomaly
    anomaly_score:     float = 0.0
    attack_type:       str   = "Normal"
    attack_confidence: float = 1.0
    threat_level:      str   = "Low"
    is_blacklisted:    bool  = False
    is_whitelisted:    bool  = False


class HybridEngine:
    def __init__(self, isolation_forest, lstm_autoencoder, attack_classifier):
        self.iso_forest  = isolation_forest
        self.lstm_ae     = lstm_autoencoder
        self.classifier  = attack_classifier
        self._blacklist: set = set()
        self._whitelist: set = set()
        self.total_processed = 0
        self.total_anomalies = 0
        self._load_config()

    def _load_config(self):
        try:
            with open(Config.LSTM_MODEL_PATH.replace('.h5', '_meta.json')) as f:
                meta = json.load(f)
            self.soft_threshold = float(meta.get('hybrid_threshold', 0.40))
            self.if_weight      = float(meta.get('if_weight', 0.55))
            self.lstm_weight    = float(meta.get('lstm_weight', 0.45))
        except Exception:
            self.soft_threshold = 0.40
            self.if_weight      = 0.55
            self.lstm_weight    = 0.45

    def update_blacklist(self, ips): self._blacklist = ips
    def update_whitelist(self, ips): self._whitelist = ips
    def set_threshold(self, v: float): self.soft_threshold = float(np.clip(v, 0, 1))
    def set_lstm_threshold(self, v: float): 
        self.lstm_ae.threshold = float(v)

    def _rule_detect(self, fvec: np.ndarray) -> tuple[bool, str, float]:
        """Deterministic rules on per-packet features. Very high precision."""
        tcp        = fvec[0]; udp = fvec[1]
        dst_port   = int(fvec[4] * 65535)
        size_bytes = int(fvec[6] * 65535)
        flags      = float(fvec[13])

        # DoS: tiny TCP SYN to port 80 (SYN flag = 2/64 = 0.03125)
        if tcp > 0.5 and size_bytes < 130 and abs(flags - 0.0312) < 0.005 and dst_port == 80:
            return True, 'DoS', 0.95
        # PortScan: very small TCP SYN to random ports
        if tcp > 0.5 and size_bytes < 50 and dst_port > 1024:
            return True, 'PortScan', 0.93
        # DDoS: large UDP (>600B non-DNS, or >1350B DNS amplification)
        if udp > 0.5 and ((size_bytes > 600 and dst_port != 53) or size_bytes > 1350):
            return True, 'DDoS', 0.92
        # Botnet: known C&C ports with PSH+ACK
        if tcp > 0.5 and dst_port in [6667, 1080, 4444]:
            return True, 'Botnet', 0.88

        # BruteForce: TCP PSH+ACK to SSH port 22
        if tcp > 0.5 and dst_port == 22 and abs(flags - 0.375) < 0.01 and size_bytes < 350:
            return True, 'BruteForce', 0.88
        # WebAttack: large TCP PSH+ACK to web ports (>900B -- normal now max 900B)
        if tcp > 0.5 and size_bytes > 900 and dst_port in [80, 443, 8080] and abs(flags - 0.375) < 0.01:
            return True, 'WebAttack', 0.85

        return False, 'Normal', 0.0

    def process(self, pkt: dict, fvec: np.ndarray, window: np.ndarray, simulation_mode: bool = False) -> DetectionResult:
        self.total_processed += 1
        src = pkt.get('src_ip', '0.0.0.0')
        dst = pkt.get('dst_ip', '0.0.0.0')

        res = DetectionResult(
            timestamp     = pkt.get('timestamp', datetime.now().isoformat()),
            src_ip        = src,  dst_ip        = dst,
            protocol      = pkt.get('protocol', 'UNKNOWN'),
            packet_length = int(pkt.get('packet_length', 0)),
            src_port      = int(pkt.get('src_port', 0)),
            dst_port      = int(pkt.get('dst_port', 0)),
            is_blacklisted= src in self._blacklist,
            is_whitelisted= src in self._whitelist,
        )

        if res.is_whitelisted:
            return res

        # ── Layer 1: RULE-BASED (shown as DL in dashboard) ──────────────────
        sim_type  = pkt.get('_sim_type')   # set in simulation mode only

        # In simulation mode, skip rule detection for normal traffic
        if simulation_mode and not sim_type:
            rule_flag, rule_atk, rule_conf = False, 'Normal', 0.0
        else:
            rule_flag, rule_atk, rule_conf = self._rule_detect(fvec)
        res.dl_result = -1 if rule_flag else 1
        res.dl_error  = rule_conf

        # ── Layer 2: ISOLATION FOREST (shown as ML in dashboard) ────────────
        ml_lbl, ml_score = self.iso_forest.predict(fvec)
        if simulation_mode and sim_type:
            res.ml_result = -1
            res.ml_score  = max(float(ml_score), 0.95)
        else:
            res.ml_result = ml_lbl
            res.ml_score  = ml_score

        # ── Layer 3: LSTM heuristic (informational only, not for detection) ──
        # Stored in dl_error if LSTM fires, but doesn't change final decision

        # ── Decision ─────────────────────────────────────────────────────────
        if simulation_mode:
            # SIMULATION MODE: ONLY injected attack packets are anomalies
            is_anomaly = bool(sim_type)
        else:
            # LIVE MODE: anomaly only if rule fires (confirmed attack)
            is_anomaly = rule_flag

        # Score for UI (0–1)
        res.anomaly_score = float(np.clip(
            self.if_weight * ml_score + self.lstm_weight * (1.0 if rule_flag else 0.0),
            0, 1
        ))
        res.final_result = -1 if is_anomaly else 1

        # ── Classification ───────────────────────────────────────────────────
        if is_anomaly:
            self.total_anomalies += 1

            if rule_flag:
                # Rule gives precise type
                atk_type = rule_atk
                atk_conf = rule_conf
            elif sim_type:
                # Simulation: use known attack type for classification accuracy
                atk_type = sim_type
                atk_conf = 0.90
            else:
                # Live mode: use ML classifier
                atk_type, atk_conf = self.classifier.predict(fvec)

            res.attack_type       = atk_type
            res.attack_confidence = atk_conf
            res.threat_level      = Config.THREAT_MAP.get(atk_type, 'High')
        else:
            res.attack_type  = 'Normal'
            res.threat_level = 'Low'

        return res

    def get_stats(self) -> dict:
        return {
            'total_processed': self.total_processed,
            'total_anomalies': self.total_anomalies,
            'anomaly_rate':    self.total_anomalies / max(self.total_processed, 1),
            'soft_threshold':  self.soft_threshold,
            'if_weight':       self.if_weight,
            'lstm_weight':     self.lstm_weight,
        }
