"""
backend/train/dataset_loaders.py
─────────────────────────────────────────────────────────────────────────────
Loaders for every major public NIDS dataset.
Each loader returns (X: np.ndarray, y: np.ndarray) where
  X has shape (n, N_FEATURES) and
  y is an array of string labels from Config.ATTACK_CLASSES.

Supported datasets
──────────────────
  1. CICIDS2017         – Canadian Institute for Cybersecurity
  2. NSL-KDD            – Improved KDD Cup 99
  3. UNSW-NB15          – University of New South Wales
  4. CIC-DDoS2019       – CIC DDoS Dataset 2019
  5. KDD Cup 99         – Original KDD 1999
  6. Custom CSV         – Any CSV with a label column (auto-detected)
  7. Synthetic          – Built-in generator (always available)
"""

import os
import logging
import numpy as np
import pandas as pd
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config import Config

logger = logging.getLogger(__name__)

# ── Canonical label mappings ──────────────────────────────────────────────────

_CICIDS_MAP = {
    "BENIGN":                        "Normal",
    "Bot":                           "Botnet",
    "DDoS":                          "DDoS",
    "DoS GoldenEye":                 "DoS",
    "DoS Hulk":                      "DoS",
    "DoS Slowhttptest":              "DoS",
    "DoS slowloris":                 "DoS",
    "FTP-Patator":                   "BruteForce",
    "Heartbleed":                    "DoS",
    "Infiltration":                  "Botnet",
    "PortScan":                      "PortScan",
    "SSH-Patator":                   "BruteForce",
    "Web Attack  Brute Force":       "WebAttack",
    "Web Attack  Sql Injection":     "WebAttack",
    "Web Attack  XSS":               "WebAttack",
    "Web Attack – Brute Force":      "WebAttack",
    "Web Attack – Sql Injection":    "WebAttack",
    "Web Attack – XSS":              "WebAttack",
}

_NSLKDD_MAP = {
    "normal": "Normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "mailbomb": "DoS",
    # PortScan / Probe
    "satan": "PortScan", "ipsweep": "PortScan", "nmap": "PortScan",
    "portsweep": "PortScan", "mscan": "PortScan", "saint": "PortScan",
    # BruteForce / R2L
    "ftp_write": "BruteForce", "guess_passwd": "BruteForce",
    "imap": "BruteForce", "multihop": "BruteForce", "phf": "BruteForce",
    "spy": "BruteForce", "warezclient": "BruteForce", "warezmaster": "BruteForce",
    "sendmail": "BruteForce", "named": "BruteForce", "snmpgetattack": "BruteForce",
    "snmpguess": "BruteForce", "xlock": "BruteForce", "xsnoop": "BruteForce",
    "httptunnel": "BruteForce",
    # Botnet / U2R
    "buffer_overflow": "Botnet", "loadmodule": "Botnet", "perl": "Botnet",
    "rootkit": "Botnet", "ps": "Botnet", "sqlattack": "Botnet",
    "xterm": "Botnet",
}

_UNSWNB15_MAP = {
    "Normal":   "Normal",
    "Analysis": "WebAttack",
    "Backdoor": "Botnet",
    "DoS":      "DoS",
    "Exploits": "WebAttack",
    "Fuzzers":  "DoS",
    "Generic":  "DoS",
    "Reconnaissance": "PortScan",
    "Shellcode":      "BruteForce",
    "Worms":          "Botnet",
}

_KDDCUP_MAP = {
    "normal.": "Normal", "normal": "Normal",
    **{k: v for k, v in _NSLKDD_MAP.items()},
}

_CICDDOS_MAP = {
    "BENIGN":              "Normal",
    "DrDoS_DNS":           "DDoS",
    "DrDoS_LDAP":          "DDoS",
    "DrDoS_MSSQL":         "DDoS",
    "DrDoS_NetBIOS":       "DDoS",
    "DrDoS_NTP":           "DDoS",
    "DrDoS_SNMP":          "DDoS",
    "DrDoS_SSDP":          "DDoS",
    "DrDoS_UDP":           "DDoS",
    "Syn":                 "DoS",
    "TFTP":                "DDoS",
    "UDP-lag":             "DDoS",
    "WebDDoS":             "DDoS",
    "UDPFlood":            "DDoS",
    "NetBIOS":             "DDoS",
    "LDAP":                "DDoS",
    "MSSQL":               "DDoS",
    "Portmap":             "DDoS",
    "SYN":                 "DoS",
}


# ── Shared utilities ──────────────────────────────────────────────────────────

def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/NaN and drop all-zero rows."""
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df


def _normalise_col(series: pd.Series) -> pd.Series:
    """Min-max normalise a series to [0, 1], handling zero-range."""
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series(np.zeros(len(series)), index=series.index)
    return (series - mn) / (mx - mn)


def _map_labels(series: pd.Series, mapping: dict, default: str = "Normal") -> pd.Series:
    stripped = series.str.strip()
    return stripped.map(lambda v: mapping.get(v, default))


def _keep_known(X: np.ndarray, y: np.ndarray) -> tuple:
    mask = np.isin(y, Config.ATTACK_CLASSES)
    return X[mask], y[mask]


# ── Feature column groups per dataset ────────────────────────────────────────
#
# Each dataset is mapped to our 17 canonical features:
#   0  proto_tcp       7  packet_rate_norm    14 flags_norm
#   1  proto_udp       8  byte_rate_norm      15 flow_pkt_count_norm
#   2  proto_icmp      9  flow_duration_norm  16 unique_dst_ports_norm
#   3  src_port_norm  10  conn_count_norm
#   4  dst_port_norm  11  size_mean_norm
#   5  is_wellknown   12  size_var_norm
#   6  pkt_size_norm  13  flags_norm (dup alias)


# ── CICIDS 2017 ───────────────────────────────────────────────────────────────

_CICIDS_COLS = {
    # dataset column            : our feature index
    "Destination Port":          4,
    "Flow Duration":             9,
    "Total Fwd Packets":         15,
    "Total Backward Packets":    10,
    "Total Length of Fwd Packets": 16,
    "Fwd Packet Length Max":     6,
    "Fwd Packet Length Mean":    11,
    "Fwd Packet Length Std":     12,
    "Flow Bytes/s":              8,
    "Flow Packets/s":            7,
    "Flow IAT Std":              13,
    "Fwd PSH Flags":             14,
    "FIN Flag Count":            13,
    "SYN Flag Count":            14,
    "Protocol":                  None,   # handled separately
}


def load_cicids2017(path: str, max_rows: int = 200_000) -> tuple:
    """Load one or more CICIDS2017 CSV files (pass a dir or single file)."""
    p = Path(path)
    files = sorted(p.glob("*.csv")) if p.is_dir() else [p]
    if not files:
        raise FileNotFoundError(f"No CSV files found at {path}")

    frames = []
    for f in files:
        logger.info(f"  Reading CICIDS2017: {f.name}")
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    if not frames:
        raise ValueError("No valid CICIDS2017 files loaded")

    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()

    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    if label_col is None:
        raise ValueError("No label column found in CICIDS2017 file")

    df[label_col] = _map_labels(df[label_col].astype(str), _CICIDS_MAP)
    df = _clean(df)

    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)

    # Protocol one-hot from numeric column
    if "Protocol" in df.columns:
        proto = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0).astype(int)
        X[:, 0] = (proto == 6).astype(np.float32)   # TCP
        X[:, 1] = (proto == 17).astype(np.float32)  # UDP
        X[:, 2] = (proto == 1).astype(np.float32)   # ICMP

    # Destination port → well-known flag
    if "Destination Port" in df.columns:
        dport = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0)
        X[:, 4] = _normalise_col(dport).values.astype(np.float32)
        X[:, 5] = (dport < 1024).astype(np.float32)

    for col, idx in _CICIDS_COLS.items():
        if idx is None or col not in df.columns:
            continue
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
        X[:, idx] = _normalise_col(vals).values.astype(np.float32)

    y = df[label_col].values
    X, y = _keep_known(X, y)
    logger.info(f"  CICIDS2017 loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── NSL-KDD ───────────────────────────────────────────────────────────────────

_NSLKDD_HEADER = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty",
]

_NSLKDD_PROTO = {"tcp": 0, "udp": 1, "icmp": 2}
_NSLKDD_FLAGS = {"SF":0, "S0":1, "REJ":2, "RSTO":3, "RSTR":4,
                 "SH":5, "S1":6, "S2":7, "S3":8, "OTH":9}


def load_nslkdd(path: str, max_rows: int = 200_000) -> tuple:
    p = Path(path)
    files = sorted(p.glob("*.txt")) + sorted(p.glob("*.csv")) if p.is_dir() else [p]
    if not files:
        raise FileNotFoundError(f"No files at {path}")

    frames = []
    for f in files:
        logger.info(f"  Reading NSL-KDD: {f.name}")
        try:
            df = pd.read_csv(f, header=None, names=_NSLKDD_HEADER,
                             low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    df = pd.concat(frames, ignore_index=True)
    df = _clean(df)

    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)

    # Protocol one-hot
    proto_int = df["protocol_type"].str.lower().map(_NSLKDD_PROTO).fillna(0).astype(int)
    X[:, 0] = (proto_int == 0).astype(np.float32)
    X[:, 1] = (proto_int == 1).astype(np.float32)
    X[:, 2] = (proto_int == 2).astype(np.float32)

    # Flags
    flag_int = df["flag"].map(_NSLKDD_FLAGS).fillna(0)
    X[:,13] = _normalise_col(flag_int).values.astype(np.float32)

    # Numeric features → feature indices
    mapping = {
        "duration":        9,
        "src_bytes":       8,
        "dst_bytes":       16,
        "count":           10,
        "srv_count":       15,
        "hot":             11,
        "wrong_fragment":  12,
        "urgent":          14,
        "num_failed_logins": 3,
        "dst_host_count":  7,
    }
    for col, idx in mapping.items():
        if col in df.columns:
            vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
            X[:, idx] = _normalise_col(vals).values.astype(np.float32)

    # Well-known port proxy from service
    common_svc = {"http", "ftp", "smtp", "ssh", "dns", "telnet", "pop3"}
    svc = df.get("service", pd.Series(["other"] * len(df))).str.lower()
    X[:, 5] = svc.isin(common_svc).astype(np.float32)

    y = _map_labels(df["label"].astype(str), _NSLKDD_MAP).values
    X, y = _keep_known(X, y)
    logger.info(f"  NSL-KDD loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── UNSW-NB15 ─────────────────────────────────────────────────────────────────

_UNSWNB_COLS = {
    "dur":      9,   "spkts":    15,  "dpkts":    10,
    "sbytes":   8,   "dbytes":   16,  "sload":    7,
    "dload":    6,   "sloss":    12,  "dloss":    11,
    "sinpkt":   13,  "proto":    None, "state":   14,
}


def load_unswnb15(path: str, max_rows: int = 200_000) -> tuple:
    p = Path(path)
    files = sorted(p.glob("*.csv")) if p.is_dir() else [p]
    if not files:
        raise FileNotFoundError(f"No CSV files at {path}")

    frames = []
    for f in files:
        logger.info(f"  Reading UNSW-NB15: {f.name}")
        try:
            df = pd.read_csv(f, low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip().str.lower()
    df = _clean(df)

    # Label column detection
    label_col = next((c for c in df.columns if "attack_cat" in c or "label" in c), None)
    if label_col is None:
        raise ValueError("Cannot find label column in UNSW-NB15")

    # If numeric label (0=normal, 1=attack) use attack_cat if available
    if "attack_cat" in df.columns:
        label_col = "attack_cat"
        df[label_col] = df[label_col].fillna("Normal").astype(str)
        y_raw = _map_labels(df[label_col], _UNSWNB15_MAP)
    else:
        y_raw = df[label_col].map(lambda v: "Normal" if str(v).strip() in ("0","normal","Normal") else "DoS")

    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)

    # Protocol
    if "proto" in df.columns:
        proto = df["proto"].str.lower().fillna("")
        X[:, 0] = (proto == "tcp").astype(np.float32)
        X[:, 1] = (proto == "udp").astype(np.float32)
        X[:, 2] = (proto == "icmp").astype(np.float32)

    # Source / dest ports
    for col, idx in [("sport", 3), ("dsport", 4)]:
        if col in df.columns:
            vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
            X[:, idx] = _normalise_col(vals).values.astype(np.float32)
            if idx == 4:
                X[:, 5] = (vals < 1024).astype(np.float32)

    for col, idx in _UNSWNB_COLS.items():
        if idx is None or col not in df.columns:
            continue
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
        X[:, idx] = _normalise_col(vals).values.astype(np.float32)

    y = y_raw.values
    X, y = _keep_known(X, y)
    logger.info(f"  UNSW-NB15 loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── CIC-DDoS 2019 ─────────────────────────────────────────────────────────────

def load_cicddos2019(path: str, max_rows: int = 200_000) -> tuple:
    """CIC-DDoS2019 has same column structure as CICIDS2017."""
    logger.info("  CIC-DDoS2019: using CICIDS2017 loader with DDoS label map")
    p = Path(path)
    files = sorted(p.glob("*.csv")) if p.is_dir() else [p]

    frames = []
    for f in files:
        logger.info(f"  Reading CIC-DDoS2019: {f.name}")
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    if not frames:
        raise ValueError("No valid CIC-DDoS2019 files")

    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()
    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    if not label_col:
        raise ValueError("No label column found")

    df[label_col] = _map_labels(df[label_col].astype(str), _CICDDOS_MAP)
    df = _clean(df)

    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)
    if "Protocol" in df.columns:
        proto = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0).astype(int)
        X[:, 0] = (proto == 6).astype(np.float32)
        X[:, 1] = (proto == 17).astype(np.float32)
        X[:, 2] = (proto == 1).astype(np.float32)

    if "Destination Port" in df.columns:
        dport = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0)
        X[:, 4] = _normalise_col(dport).values.astype(np.float32)
        X[:, 5] = (dport < 1024).astype(np.float32)

    for col, idx in _CICIDS_COLS.items():
        if idx is None or col not in df.columns:
            continue
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
        X[:, idx] = _normalise_col(vals).values.astype(np.float32)

    y = df[label_col].values
    X, y = _keep_known(X, y)
    logger.info(f"  CIC-DDoS2019 loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── KDD Cup 99 ────────────────────────────────────────────────────────────────

_KDD99_HEADER = _NSLKDD_HEADER[:-1]   # no "difficulty" column


def load_kddcup99(path: str, max_rows: int = 200_000) -> tuple:
    p = Path(path)
    files = sorted(p.glob("*.gz")) + sorted(p.glob("*.csv")) + sorted(p.glob("*.txt"))
    if p.is_file():
        files = [p]
    if not files:
        raise FileNotFoundError(f"No files at {path}")

    frames = []
    for f in files:
        logger.info(f"  Reading KDD Cup 99: {f.name}")
        try:
            if str(f).endswith(".gz"):
                df = pd.read_csv(f, header=None, names=_KDD99_HEADER,
                                 compression="gzip", low_memory=False, nrows=max_rows)
            else:
                df = pd.read_csv(f, header=None, names=_KDD99_HEADER,
                                 low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    df = pd.concat(frames, ignore_index=True)
    df = _clean(df)

    # Reuse NSL-KDD feature mapping (identical schema)
    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)

    proto_int = df["protocol_type"].str.lower().map(_NSLKDD_PROTO).fillna(0).astype(int)
    X[:, 0] = (proto_int == 0).astype(np.float32)
    X[:, 1] = (proto_int == 1).astype(np.float32)
    X[:, 2] = (proto_int == 2).astype(np.float32)

    flag_int = df["flag"].map(_NSLKDD_FLAGS).fillna(0)
    X[:, 13] = _normalise_col(flag_int).values.astype(np.float32)

    mapping = {"duration": 9, "src_bytes": 8, "dst_bytes": 16,
               "count": 10, "srv_count": 15, "hot": 11,
               "wrong_fragment": 12, "dst_host_count": 7}
    for col, idx in mapping.items():
        if col in df.columns:
            vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
            X[:, idx] = _normalise_col(vals).values.astype(np.float32)

    # KDD99 labels end with "."
    y_raw = df["label"].astype(str).str.rstrip(".")
    y = _map_labels(y_raw, _KDDCUP_MAP).values
    X, y = _keep_known(X, y)
    logger.info(f"  KDD Cup 99 loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── Generic / Custom CSV ──────────────────────────────────────────────────────

_GENERIC_NUMERIC_CANDIDATES = [
    "duration", "src_bytes", "dst_bytes", "flow_duration",
    "total_fwd_packets", "total_bwd_packets", "flow_bytes_s",
    "flow_packets_s", "fwd_packet_length_mean", "fwd_packet_length_std",
    "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fwd_psh_flags", "syn_flag_count", "fin_flag_count",
    "destination_port", "protocol",
]


def load_custom_csv(path: str, label_col: str | None = None,
                    max_rows: int = 200_000,
                    label_map: dict | None = None) -> tuple:
    """
    Load any CSV and auto-map columns to our 17 features.
    label_col : name of the label column (auto-detected if None)
    label_map : optional custom {raw_label: canonical_label} dict
    """
    p = Path(path)
    files = sorted(p.glob("*.csv")) if p.is_dir() else [p]
    if not files:
        raise FileNotFoundError(f"No CSV files at {path}")

    frames = []
    for f in files:
        logger.info(f"  Reading custom CSV: {f.name}")
        try:
            df = pd.read_csv(f, low_memory=False, nrows=max_rows)
            frames.append(df)
        except Exception as e:
            logger.warning(f"  Skipped {f.name}: {e}")

    df = pd.concat(frames, ignore_index=True)
    df.columns = [c.strip().lower().replace(" ", "_").replace("/", "_") for c in df.columns]
    df = _clean(df)

    # Auto-detect label column
    if label_col is None:
        candidates = ["label", "attack", "class", "category",
                      "attack_type", "attack_cat", "traffic_type"]
        label_col  = next((c for c in candidates if c in df.columns), None)
        if label_col is None:
            raise ValueError(f"Cannot auto-detect label column. Columns: {list(df.columns[:10])}")

    logger.info(f"  Using label column: '{label_col}'")

    # Build label mapping
    if label_map is None:
        unique_vals = df[label_col].astype(str).str.strip().unique()
        label_map = {}
        for v in unique_vals:
            vl = v.lower()
            if any(x in vl for x in ["normal","benign","legitimate"]):
                label_map[v] = "Normal"
            elif any(x in vl for x in ["ddos","distributed"]):
                label_map[v] = "DDoS"
            elif any(x in vl for x in ["dos","flood","hulk","slowloris"]):
                label_map[v] = "DoS"
            elif any(x in vl for x in ["scan","sweep","probe","recon"]):
                label_map[v] = "PortScan"
            elif any(x in vl for x in ["brute","patator","guess","login"]):
                label_map[v] = "BruteForce"
            elif any(x in vl for x in ["bot","backdoor","worm","rootkit"]):
                label_map[v] = "Botnet"
            elif any(x in vl for x in ["web","sql","xss","injection"]):
                label_map[v] = "WebAttack"
            else:
                label_map[v] = "DoS"   # default unknown attacks → DoS

    y = df[label_col].astype(str).str.strip().map(label_map).fillna("Normal").values

    # Map numeric columns → feature indices (best-effort)
    X = np.zeros((len(df), Config.N_FEATURES), dtype=np.float32)

    col_map = {
        "protocol":                     None,   # handled below
        "destination_port":             4,
        "dst_port":                     4,
        "flow_duration":                9,
        "duration":                     9,
        "total_fwd_packets":            15,
        "total_bwd_packets":            10,
        "flow_bytes_s":                 8,
        "flow_packets_s":               7,
        "fwd_packet_length_mean":       11,
        "fwd_packet_length_std":        12,
        "packet_length_mean":           11,
        "packet_length_variance":       12,
        "syn_flag_count":               14,
        "fin_flag_count":               13,
        "src_bytes":                    8,
        "dst_bytes":                    16,
        "count":                        10,
    }

    if "protocol" in df.columns:
        p_val = pd.to_numeric(df["protocol"], errors="coerce").fillna(0).astype(int)
        X[:, 0] = (p_val == 6).astype(np.float32)
        X[:, 1] = (p_val == 17).astype(np.float32)
        X[:, 2] = (p_val == 1).astype(np.float32)
    elif "protocol_type" in df.columns:
        pt = df["protocol_type"].str.lower().fillna("")
        X[:, 0] = (pt == "tcp").astype(np.float32)
        X[:, 1] = (pt == "udp").astype(np.float32)
        X[:, 2] = (pt == "icmp").astype(np.float32)

    for col, idx in col_map.items():
        if idx is None or col not in df.columns:
            continue
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0)
        X[:, idx] = _normalise_col(vals).values.astype(np.float32)
        if col in ("destination_port", "dst_port"):
            X[:, 5] = (vals < 1024).astype(np.float32)

    X, y = _keep_known(X, y)
    logger.info(f"  Custom CSV loaded: {X.shape[0]} rows, classes={dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y


# ── Dataset registry ──────────────────────────────────────────────────────────

DATASET_LOADERS = {
    "cicids2017":    load_cicids2017,
    "nslkdd":        load_nslkdd,
    "unswnb15":      load_unswnb15,
    "cicddos2019":   load_cicddos2019,
    "kddcup99":      load_kddcup99,
    "custom":        load_custom_csv,
}


def auto_detect_dataset(path: str) -> str:
    """
    Heuristic dataset type detection from path or file headers.
    Returns one of DATASET_LOADERS keys.
    """
    p = Path(path)
    name = p.name.lower()

    if "cicids" in name or "cicids2017" in name:
        return "cicids2017"
    if "nsl" in name or "kddtrain" in name or "kddtest" in name:
        return "nslkdd"
    if "unsw" in name:
        return "unswnb15"
    if "cicddos" in name or "ddos2019" in name:
        return "cicddos2019"
    if "kddcup" in name or "kdd99" in name:
        return "kddcup99"

    # Peek at headers
    try:
        sample = []
        if p.is_dir():
            csvs = list(p.glob("*.csv"))
            if csvs:
                sample = pd.read_csv(csvs[0], nrows=1).columns.str.strip().str.lower().tolist()
        else:
            sample = pd.read_csv(p, nrows=1).columns.str.strip().str.lower().tolist()

        joined = " ".join(sample)
        if "flow bytes/s" in joined or "flow packets/s" in joined:
            if "ddos" in name:
                return "cicddos2019"
            return "cicids2017"
        if "protocol_type" in joined and "srv_count" in joined:
            return "nslkdd" if "difficulty" not in joined else "nslkdd"
        if "attack_cat" in joined or "dur" in joined and "spkts" in joined:
            return "unswnb15"
    except Exception:
        pass

    return "custom"
