# 🛡️ NIDS Sentinel
### Network Intrusion Detection System — Hybrid ML + DL

> Real-time zero-day attack detection using **Isolation Forest** + **LSTM Autoencoder** with a professional SOC-style dashboard.

---

## 📐 Architecture

```
Live Network Packets
      │
      ▼
 Packet Capture (Scapy / Simulation)
      │
      ▼
 Feature Extraction  ──► 17 features (rate, flow, statistical, protocol)
      │
      ├──► Isolation Forest (ML)  ──► anomaly score
      │
      └──► LSTM Autoencoder (DL) ──► reconstruction error
                │
                ▼
        Hybrid Decision Engine
         (weighted soft scoring)
                │
          ┌─────┴─────┐
         NORMAL      ANOMALY
                        │
                        ▼
              Attack Classifier (RF)
              DoS / DDoS / PortScan /
              BruteForce / Botnet / WebAttack
                        │
                        ▼
                  MySQL Storage
                        │
                        ▼
              Dashboard (WebSocket)
```

---

## 🚀 Quick Start

### 1 — Install Dependencies

```bash
pip install -r requirements.txt
```

> **Optional:** For TensorFlow LSTM support:
> ```bash
> pip install tensorflow>=2.15.0
> ```
>
> Without TensorFlow the system falls back to a temporal-variance heuristic for the DL component — all other functionality is identical.

### 2 — Configure (optional)

```bash
cp .env.example .env
# Edit .env with your MySQL credentials etc.
```

### 3 — Train Models

```bash
# Synthetic data (no dataset required):
python run.py --train

# With CICIDS2017 dataset (better accuracy):
python run.py --train --dataset /path/to/cicids2017.csv
```

### 4 — Run

```bash
# Simulation mode (recommended for demo — no root needed):
python run.py

# Live capture mode (requires root / sudo):
sudo python run.py --live
```

Open **http://localhost:5000** — log in with `admin` / `nids@2024`.

---

## 🔐 Default Credentials

| User      | Password     | Role    |
|-----------|-------------|---------|
| admin     | nids@2024   | Admin   |
| analyst   | analyst@2024| Analyst |

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| **Live Packet Log** | Real-time table auto-updating via WebSocket |
| **Stats Cards** | Total packets, anomalies, active threats, threat level |
| **Traffic Chart** | Packets-per-second line chart (last 60 s) |
| **Attack Pie** | Distribution of detected attack types |
| **Live Alerts** | Blinking alert panel with sound toggle |
| **Top Attackers** | Bar chart of most active attacker IPs |
| **Full Log Table** | Searchable, filterable, paginated log with CSV export |
| **IP Blacklist** | Block specific IPs — flagged as anomaly regardless |
| **IP Whitelist** | Trust specific IPs — always marked normal |
| **Threshold Tuning** | Slider to adjust hybrid & LSTM thresholds live |
| **Attack Simulation** | Inject DoS / DDoS / PortScan / BruteForce / Botnet / WebAttack bursts |
| **CSV Export** | Download all logs as a CSV file |

---

## 🧠 Models

### Isolation Forest (ML)
- Trained **only on normal traffic**
- `n_estimators=200`, `contamination=0.05`
- Output: +1 normal / −1 anomaly + normalised score

### LSTM Autoencoder (DL)
- Learns sequential behaviour of normal traffic
- Input: sliding window of 10 packets × 17 features
- Anomaly = reconstruction error > calibrated threshold
- Threshold auto-calibrated as `mean + 3σ` of training errors

### Hybrid Decision Engine
- **Soft mode** (default): weighted score = `0.4 × IF_score + 0.6 × DL_score`
- Anomaly if combined score > threshold (default 0.30)
- Threshold tunable live from UI

### Attack Classifier (Random Forest)
- `n_estimators=200`, `class_weight="balanced"`
- 7 classes: Normal, DoS, DDoS, PortScan, BruteForce, Botnet, WebAttack
- Only invoked when hybrid engine flags anomaly

---

## 📦 Extracted Features (17 total)

| # | Feature | Description |
|---|---------|-------------|
| 1-3 | proto_tcp/udp/icmp | Protocol one-hot encoding |
| 4-5 | src/dst_port_norm | Normalised port numbers |
| 6 | is_wellknown_port | Port < 1024 flag |
| 7 | pkt_size_norm | Packet size normalised |
| 8 | packet_rate_norm | Packets/sec from src IP |
| 9 | byte_rate_norm | Bytes/sec from src IP |
| 10 | flow_duration_norm | Duration of current flow |
| 11 | conn_count_norm | Unique connections from src |
| 12-13 | size_mean/var_norm | Flow packet size statistics |
| 14 | flags_norm | TCP flags value normalised |
| 15 | flow_pkt_count_norm | Total packets in flow |
| 16 | flow_bytes_norm | Total bytes in flow |
| 17 | unique_dst_ports_norm | Port scan indicator |

---

## 🗄️ Database Schema

```
packets    — raw packet metadata
features   — JSON feature vectors
results    — detection results (ml, dl, final, attack_type, threat_level)
alerts     — high-severity alert log
blacklist  — blocked IP addresses
whitelist  — trusted IP addresses
```

---

## 🔥 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate |
| POST | `/api/logout` | End session |
| GET | `/api/stats` | System statistics |
| GET | `/api/live-data` | Same as stats |
| GET | `/api/logs` | Paginated log table |
| GET | `/api/alerts` | Recent alerts |
| GET | `/api/export-csv` | Download logs as CSV |
| POST | `/api/simulate` | Inject attack burst `{"type":"DoS"}` |
| POST | `/api/simulate/stop` | Stop injection |
| POST | `/api/threshold` | Update thresholds `{"hybrid":0.3,"lstm":0.04}` |
| GET/POST/DELETE | `/api/blacklist` | Manage blacklist |
| GET/POST/DELETE | `/api/whitelist` | Manage whitelist |

WebSocket events (Socket.IO):
- `new_packet` — emitted per packet processed
- `new_alert`  — emitted when anomaly detected
- `stats_update` — emitted every second with full stats

---

## ⚡ Simulating Attacks (Demo)

From the dashboard **Simulate** tab, or via API:

```bash
# DoS flood
curl -X POST http://localhost:5000/api/simulate \
     -H 'Content-Type: application/json' \
     -d '{"type":"DoS"}'

# Port scan
curl -X POST http://localhost:5000/api/simulate \
     -d '{"type":"PortScan"}' -H 'Content-Type: application/json'
```

Or use real tools (live capture mode with sudo):
```bash
ping -f 127.0.0.1         # ICMP flood
nmap -sS 127.0.0.1        # SYN scan
hydra ssh://127.0.0.1     # brute force
```

---

## 📁 Project Structure

```
nids_project/
├── run.py                          # Main entry point
├── config.py                       # All configuration
├── requirements.txt
├── .env.example
│
├── backend/
│   ├── app.py                      # Flask + SocketIO server
│   ├── feature_extractor.py        # 17-feature extraction engine
│   ├── packet_capture.py           # Scapy live + simulation mode
│   │
│   ├── models/
│   │   ├── isolation_forest_model.py   # IF anomaly detector
│   │   ├── lstm_autoencoder.py         # LSTM AE deep detector
│   │   ├── attack_classifier.py        # RF multi-class classifier
│   │   └── hybrid_engine.py            # Decision fusion engine
│   │
│   ├── database/
│   │   ├── schema.sql              # MySQL DDL
│   │   └── db.py                   # Connection pool + helpers
│   │
│   ├── train/
│   │   └── train_all.py            # Training orchestrator + data gen
│   │
│   └── saved_models/               # Trained model artifacts
│       ├── isolation_forest.joblib
│       ├── scaler.joblib
│       ├── attack_classifier.joblib
│       ├── attack_classifier_scaler.joblib
│       ├── label_encoder.joblib
│       └── lstm_autoencoder.h5     # (if TF installed)
│
└── frontend/
    ├── index.html                  # Main SOC dashboard
    ├── login.html                  # Secure login page
    ├── css/style.css               # Dark cybersecurity theme
    └── js/dashboard.js             # Charts, WebSocket, UI logic
```

---

## 🎓 Key Design Decisions (Viva Points)

1. **Hybrid reduces false positives** — both models must agree (or combined weighted score must exceed threshold) before flagging
2. **LSTM captures temporal patterns** — sequential packet behaviour that IF alone cannot detect
3. **Zero-day capable** — trained only on normal traffic, any deviation is anomalous
4. **Graceful degradation** — works without TF/MySQL with heuristic fallbacks
5. **Real-time via WebSocket** — sub-second latency from capture to dashboard
6. **Adjustable sensitivity** — threshold slider allows operators to tune FP/FN tradeoff live
