import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Load .env file if present (check both nids_project/ and parent directory)
def _load_env():
    candidates = [BASE_DIR / ".env", BASE_DIR.parent / ".env"]
    for _env_path in candidates:
        if _env_path.exists():
            for line in _env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()   # override, not setdefault
            break  # use first found

_load_env()

class Config:
    # ── Database ──────────────────────────────────────────────
    DB_HOST     = os.getenv("DB_HOST",     "localhost")
    DB_PORT     = int(os.getenv("DB_PORT", "3306"))
    DB_NAME     = os.getenv("DB_NAME",     "nids_db")
    DB_USER     = os.getenv("DB_USER",     "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password")

    # ── Flask ─────────────────────────────────────────────────
    SECRET_KEY  = os.getenv("SECRET_KEY",  "nids-ultra-secret-2024")
    DEBUG       = os.getenv("DEBUG",       "False") == "True"
    HOST        = os.getenv("HOST",        "0.0.0.0")
    PORT        = int(os.getenv("PORT",    "5000"))

    # ── Auth ──────────────────────────────────────────────────
    PLAIN_USERS = {
        "admin":   "nids@2024",
        "analyst": "analyst@2024",
    }

    # ── Models ────────────────────────────────────────────────
    MODEL_DIR        = str(BASE_DIR / "backend" / "saved_models")
    IF_MODEL_PATH    = str(BASE_DIR / "backend" / "saved_models" / "isolation_forest.joblib")
    LSTM_MODEL_PATH  = str(BASE_DIR / "backend" / "saved_models" / "lstm_autoencoder.h5")
    SCALER_PATH      = str(BASE_DIR / "backend" / "saved_models" / "scaler.joblib")
    CLASSIFIER_PATH  = str(BASE_DIR / "backend" / "saved_models" / "attack_classifier.joblib")
    LABEL_ENC_PATH   = str(BASE_DIR / "backend" / "saved_models" / "label_encoder.joblib")

    # ── Detection ─────────────────────────────────────────────
    IF_CONTAMINATION = float(os.getenv("IF_CONTAMINATION", "0.02"))
    LSTM_THRESHOLD   = float(os.getenv("LSTM_THRESHOLD",   "1.165"))
    WINDOW_SIZE      = int(os.getenv("WINDOW_SIZE",        "10"))
    N_FEATURES       = 17

    # ── Network ───────────────────────────────────────────────
    NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", None)
    CAPTURE_FILTER    = os.getenv("CAPTURE_FILTER",    "ip")
    SIMULATION_MODE   = os.getenv("SIMULATION_MODE",   "True") == "True"

    # ── Dashboard ─────────────────────────────────────────────
    MAX_LOG_ENTRIES = 2000
    MAX_ALERTS      = 500

    # ── Hybrid weights ────────────────────────────────────────
    IF_WEIGHT   = 0.5
    LSTM_WEIGHT = 0.5

    # ── Attack classes ────────────────────────────────────────
    ATTACK_CLASSES = ["Normal","DoS","DDoS","PortScan","BruteForce","Botnet","WebAttack"]
    THREAT_MAP = {
        "Normal":"Low","DoS":"High","DDoS":"Critical",
        "PortScan":"Medium","BruteForce":"High",
        "Botnet":"Critical","WebAttack":"High",
    }

    # ── Qwen AI ───────────────────────────────────────────────
    QWEN_API_KEY  = os.getenv("QWEN_API_KEY",  "")
    QWEN_MODEL    = os.getenv("QWEN_MODEL",    "qwen/qwen2.5-coder-32b-instruct")
    QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://openrouter.ai/api/v1")

    # ── Datasets ──────────────────────────────────────────────
    DATASETS_DIR = str(BASE_DIR / "datasets")
