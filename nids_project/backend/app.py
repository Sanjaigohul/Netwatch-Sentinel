"""
backend/app.py – Flask + Flask-SocketIO backend
REST API + WebSocket real-time NIDS server
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import csv
import io
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, jsonify, session, Response,
                   send_from_directory, redirect, url_for)
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from config import Config
from backend.feature_extractor             import FeatureExtractor
from backend.packet_capture                import start_live_capture, start_simulation, trigger_attack, stop_attack
from backend.models.isolation_forest_model import IsolationForestModel
from backend.models.lstm_autoencoder       import LSTMAutoencoder
from backend.models.attack_classifier      import AttackClassifier
from backend.models.hybrid_engine          import HybridEngine
from backend.geoip                         import lookup as geo_lookup, lookup_async
from backend.ai_analyst                    import analyze_alert

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  [%(name)s]  %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend')

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path='',
)
app.secret_key = Config.SECRET_KEY
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)

# ── Global state ──────────────────────────────────────────────────────────────
feature_extractor = FeatureExtractor(window_size=Config.WINDOW_SIZE)
if_model          = IsolationForestModel()
lstm_model        = LSTMAutoencoder()
clf_model         = AttackClassifier()
hybrid            = HybridEngine(if_model, lstm_model, clf_model)

# In-memory log buffers (last N entries)
_log_buffer:   deque = deque(maxlen=Config.MAX_LOG_ENTRIES)
_alert_buffer: deque = deque(maxlen=Config.MAX_ALERTS)

# Packet rate tracking
_pkt_rate_ts: deque  = deque(maxlen=300)   # timestamps of last 300 packets
_pps_history: deque  = deque(maxlen=60)    # packets-per-second, last 60 s

# Runtime flags
_capture_running = False
_db_available    = False
_mem_blacklist: dict = {}   # ip -> reason (no-DB mode)
_mem_whitelist: dict = {"127.0.0.1": "Localhost", "::1": "IPv6 loopback"}

# ─────────────────────────────────────────────────────────────────────────────
#  Database (optional – silently disabled if MySQL not reachable)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from backend.database import db as _db
    _db.init_db()
    _db_available = True
    logger.info("✅ MySQL database connected successfully")
except Exception as _e:
    logger.warning(f"⚠️  MySQL not available: {_e}")
    logger.warning("   To connect MySQL: copy .env.example to .env and set DB credentials")
    _db = None


# ─────────────────────────────────────────────────────────────────────────────
#  Model loading
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
#  Authentication helpers
# ─────────────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _check_credentials(username: str, password: str) -> bool:
    return Config.PLAIN_USERS.get(username) == password


# ─────────────────────────────────────────────────────────────────────────────
#  Blacklist / Whitelist cache refresh
# ─────────────────────────────────────────────────────────────────────────────
def _refresh_lists():  # noqa: E302
    if _db_available:
        bl = {r["ip_address"] for r in _db.get_blacklist()}
        wl = {r["ip_address"] for r in _db.get_whitelist()}
    else:
        bl = set(_mem_blacklist.keys())
        wl = set(_mem_whitelist.keys()) | {"127.0.0.1", "::1"}
    hybrid.update_blacklist(bl)
    hybrid.update_whitelist(wl)


def load_models():
    """Load saved models from disk (falls back to heuristics if missing)."""
    loaded_if   = if_model.load()
    loaded_lstm = lstm_model.load()
    loaded_clf  = clf_model.load()
    if not (loaded_if and loaded_clf):
        logger.warning("Some models missing – using heuristic fallbacks (run: python run.py --train)")
    _refresh_lists()


load_models()


# ─────────────────────────────────────────────────────────────────────────────
#  Core pipeline thread
# ─────────────────────────────────────────────────────────────────────────────
from backend.packet_capture import packet_queue

def _pipeline_worker():
    """Consumes packets from queue, runs detection, emits via socket."""
    global _capture_running
    last_list_refresh = time.time()
    last_pps_update   = time.time()
    pps_counter       = 0

    logger.info("Detection pipeline started")
    while True:
        try:
            pkt = packet_queue.get(timeout=1.0)
        except Exception:
            continue

        try:
            # ── Feature extraction ────────────────────────────────────────
            fvec   = feature_extractor.extract(pkt)
            window = feature_extractor.get_window(fvec)

            # ── Hybrid detection ──────────────────────────────────────────
            result = hybrid.process(pkt, fvec, window, simulation_mode=Config.SIMULATION_MODE)

            now = datetime.now()
            _pkt_rate_ts.append(now.timestamp())
            pps_counter += 1

            # ── Build log entry ───────────────────────────────────────────
            # GeoIP lookup (cached, fast for seen IPs)
            geo_src = geo_lookup(result.src_ip)
            geo_dst = geo_lookup(result.dst_ip)

            entry = {
                "id":                  None,
                "timestamp":           result.timestamp,
                "src_ip":              result.src_ip,
                "dst_ip":              result.dst_ip,
                "protocol":            result.protocol,
                "packet_length":       result.packet_length,
                "bytes":               pkt.get("bytes", result.packet_length),
                "duration":            round(feature_extractor.last_duration, 4),
                "src_country":         geo_src.get("country", "—"),
                "src_country_code":    geo_src.get("country_code", ""),
                "src_flag":            geo_src.get("flag", "🌐"),
                "src_isp":             geo_src.get("isp", "—"),
                "dst_country":         geo_dst.get("country", "—"),
                "dst_flag":            geo_dst.get("flag", "🌐"),
                "dst_isp":             geo_dst.get("isp", "—"),
                "ml_result":           result.ml_result,
                "dl_result":           result.dl_result,
                "final_result":        result.final_result,
                "anomaly_score":       round(result.anomaly_score, 4),
                "reconstruction_error": round(result.dl_error, 6),
                "attack_type":         result.attack_type,
                "threat_level":        result.threat_level,
                "is_blacklisted":      result.is_blacklisted,
            }
            _log_buffer.appendleft(entry)

            # ── Database persist ──────────────────────────────────────────
            if _db_available:
                _persist_to_db(pkt, fvec, result)

            # ── WebSocket: live packet ────────────────────────────────────
            socketio.emit("new_packet", entry)

            # ── Alert handling (all traffic goes to live feed) ────────────
            alert_attack_type = result.attack_type
            if result.is_blacklisted and result.final_result == 1:
                alert_attack_type = "Blocked"
            alert = {
                "timestamp":     result.timestamp,
                "src_ip":        result.src_ip,
                "dst_ip":        result.dst_ip,
                "attack_type":   alert_attack_type,
                "threat_level":  result.threat_level if result.final_result == -1 else "Info",
                "anomaly_score": round(result.anomaly_score, 4),
                "src_country":   geo_src.get("country", "—"),
                "src_flag":      geo_src.get("flag", "🌐"),
                "src_isp":       geo_src.get("isp", "—"),
                "protocol":      result.protocol,
                "packet_length": result.packet_length,
                "final_result":  result.final_result,
                "is_blacklisted": result.is_blacklisted,
            }
            _alert_buffer.appendleft(alert)
            socketio.emit("new_alert", alert)

            # Persist anomalies to DB
            if result.final_result == -1 and _db_available:
                try:
                    _db.insert_alert({
                        **alert,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    })
                except Exception:
                    pass

            # ── PPS update (every second) ─────────────────────────────────
            if time.time() - last_pps_update >= 1.0:
                recent = [t for t in _pkt_rate_ts
                          if time.time() - t <= 1.0]
                pps = len(recent)
                _pps_history.append(pps)
                pps_counter = 0
                last_pps_update = time.time()

                # Emit stats
                socketio.emit("stats_update", _build_stats())

            # ── Refresh lists every 30 s ──────────────────────────────────
            if time.time() - last_list_refresh > 30:
                _refresh_lists()
                last_list_refresh = time.time()

        except Exception as exc:
            logger.exception(f"Pipeline error: {exc}")


def _persist_to_db(pkt, fvec, result):
    try:
        pkt_row = {
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "src_ip":       result.src_ip,
            "dst_ip":       result.dst_ip,
            "src_port":     pkt.get("src_port", 0),
            "dst_port":     pkt.get("dst_port", 0),
            "protocol":     result.protocol,
            "protocol_num": pkt.get("protocol_num", 0),
            "packet_length":result.packet_length,
            "flags":        str(pkt.get("flags", "")),
            "ttl":          pkt.get("ttl", 0),
        }
        pkt_id = _db.insert_packet(pkt_row)
        _db.insert_features(pkt_id, fvec)
        _db.insert_result({
            "packet_id":            pkt_id,
            "timestamp":            pkt_row["timestamp"],
            "src_ip":               result.src_ip,
            "dst_ip":               result.dst_ip,
            "protocol":             result.protocol,
            "ml_result":            result.ml_result,
            "dl_result":            result.dl_result,
            "final_result":         result.final_result,
            "anomaly_score":        round(result.anomaly_score, 4),
            "reconstruction_error": round(result.dl_error, 6),
            "attack_type":          result.attack_type,
            "threat_level":         result.threat_level,
            "is_blacklisted":       int(result.is_blacklisted),
        })
    except Exception as exc:
        logger.debug(f"DB persist error: {exc}")


def _build_stats() -> dict:
    total  = hybrid.total_processed
    anoms  = hybrid.total_anomalies
    recent = [e for e in _log_buffer
              if e["final_result"] == -1][:50]

    attack_dist: dict[str, int] = {}
    for e in _log_buffer:
        if e["final_result"] == -1:
            attack_dist[e["attack_type"]] = attack_dist.get(e["attack_type"], 0) + 1

    top_attackers_raw: dict[str, int] = {}
    for e in _log_buffer:
        if e["final_result"] == -1:
            top_attackers_raw[e["src_ip"]] = top_attackers_raw.get(e["src_ip"], 0) + 1
    top_attackers = sorted(top_attackers_raw.items(), key=lambda x: x[1], reverse=True)[:10]

    pps = list(_pps_history)

    return {
        "total_packets":     total,
        "anomalies":         anoms,
        "active_threats":    sum(1 for e in _log_buffer
                                 if e["final_result"] == -1),
        "normal_count":      total - anoms,
        "attack_distribution": attack_dist,
        "top_attackers":     [{"ip": ip, "count": c} for ip, c in top_attackers],
        "pps_history":       pps,
        "current_pps":       pps[-1] if pps else 0,
        "threshold":         hybrid.soft_threshold,
        "lstm_threshold":    lstm_model.threshold,
        "if_weight":         hybrid.if_weight,
        "simulation_mode":   Config.SIMULATION_MODE,
        "db_available":      _db_available,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────────────────────────────────────
def start_system():
    global _capture_running
    if _capture_running:
        return
    _capture_running = True

    # Choose capture mode
    if Config.SIMULATION_MODE:
        start_simulation()
        logger.info("Running in SIMULATION mode")
    else:
        start_live_capture()
        logger.info("Live packet capture started")

    # Start pipeline consumer
    t = threading.Thread(target=_pipeline_worker, daemon=True, name="pipeline")
    t.start()


# ─────────────────────────────────────────────────────────────────────────────
#  Routes – Frontend
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login_page"))
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(FRONTEND_DIR, "login.html")


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Auth
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if _check_credentials(username, password):
        session["logged_in"] = True
        session["username"]  = username
        return jsonify({"success": True, "username": username})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/whoami")
def api_whoami():
    if session.get("logged_in"):
        return jsonify({"username": session.get("username"), "logged_in": True})
    return jsonify({"logged_in": False})


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Core data
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/live-data")
@login_required
def api_live_data():
    return jsonify(_build_stats())


@app.route("/api/logs")
@login_required
def api_logs():
    page        = int(request.args.get("page",   1))
    per_page    = int(request.args.get("limit",  50))
    search      = request.args.get("search",     "")
    threat      = request.args.get("threat",     "")
    result_f    = request.args.get("result",     "")
    time_range  = request.args.get("time_range", "")

    # Filter in-memory buffer
    logs = list(_log_buffer)

    if search:
        s = search.lower()
        logs = [l for l in logs
                if s in l.get("src_ip", "").lower()
                or s in l.get("dst_ip", "").lower()
                or s in l.get("attack_type", "").lower()
                or s in l.get("protocol", "").lower()
                or s in l.get("src_country", "").lower()
                or s in l.get("src_isp", "").lower()]
    if threat:
        logs = [l for l in logs if l.get("threat_level", "") == threat]
    if result_f == "anomaly":
        logs = [l for l in logs if l["final_result"] == -1]
    elif result_f == "normal":
        logs = [l for l in logs if l["final_result"] == 1]
    if time_range:
        cutoff = datetime.now() - timedelta(minutes=int(time_range))
        logs = [l for l in logs
                if _parse_ts(l["timestamp"]) >= cutoff]

    total    = len(logs)
    start_i  = (page - 1) * per_page
    paginated = logs[start_i:start_i + per_page]

    return jsonify({
        "logs":    paginated,
        "total":   total,
        "page":    page,
        "pages":   max(1, (total + per_page - 1) // per_page),
    })


@app.route("/api/alerts")
@login_required
def api_alerts():
    limit = int(request.args.get("limit", 20))
    return jsonify(list(_alert_buffer)[:limit])


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(_build_stats())


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Blacklist / Whitelist
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/blacklist", methods=["GET"])
@login_required
def api_get_blacklist():
    if _db_available:
        return jsonify(_db.get_blacklist())
    # No-DB mode: return in-memory list with full structure
    result = [{"ip_address": ip, "reason": _mem_blacklist.get(ip, ""), "added_by": "admin"}
              for ip in hybrid._blacklist]
    return jsonify(result)


@app.route("/api/blacklist", methods=["POST"])
@login_required
def api_add_blacklist():
    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Manual")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if _db_available:
        _db.add_to_blacklist(ip, reason, session.get("username", "admin"))
    hybrid._blacklist.add(ip)
    _mem_blacklist[ip] = reason
    _refresh_lists()
    return jsonify({"success": True, "ip": ip})


@app.route("/api/blacklist/<ip>", methods=["DELETE"])
@login_required
def api_remove_blacklist(ip):
    if _db_available:
        _db.remove_from_blacklist(ip)
    hybrid._blacklist.discard(ip)
    _mem_blacklist.pop(ip, None)
    _refresh_lists()
    return jsonify({"success": True})


@app.route("/api/whitelist", methods=["GET"])
@login_required
def api_get_whitelist():
    if _db_available:
        return jsonify(_db.get_whitelist())
    result = [{"ip_address": ip, "reason": _mem_whitelist.get(ip, ""), "added_by": "admin"}
              for ip in hybrid._whitelist]
    return jsonify(result)


@app.route("/api/whitelist", methods=["POST"])
@login_required
def api_add_whitelist():
    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Trusted")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if _db_available:
        _db.add_to_whitelist(ip, reason, session.get("username", "admin"))
    hybrid._whitelist.add(ip)
    _mem_whitelist[ip] = reason
    _refresh_lists()
    return jsonify({"success": True, "ip": ip})


@app.route("/api/whitelist/<ip>", methods=["DELETE"])
@login_required
def api_remove_whitelist(ip):
    if _db_available:
        _db.remove_from_whitelist(ip)
    hybrid._whitelist.discard(ip)
    _mem_whitelist.pop(ip, None)
    _refresh_lists()
    return jsonify({"success": True})


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Threshold tuning
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/threshold", methods=["POST"])
@login_required
def api_set_threshold():
    data = request.get_json() or {}
    if "hybrid" in data:
        hybrid.set_threshold(float(data["hybrid"]))
    if "lstm" in data:
        hybrid.set_lstm_threshold(float(data["lstm"]))
    return jsonify({
        "hybrid_threshold": hybrid.soft_threshold,
        "lstm_threshold":   lstm_model.threshold,
    })


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Attack simulation (demo)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/simulate", methods=["POST"])
@login_required
def api_simulate():
    data        = request.get_json() or {}
    attack_type = data.get("type", None)
    trigger_attack(attack_type)
    return jsonify({"success": True, "attack": attack_type or "random"})


@app.route("/api/simulate/stop", methods=["POST"])
@login_required
def api_simulate_stop():
    stop_attack()
    return jsonify({"success": True})


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – CSV export
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/export-csv")
@login_required
def api_export_csv():
    logs    = list(_log_buffer)
    fields  = ["timestamp", "src_ip", "dst_ip", "protocol",
               "packet_length", "ml_result", "dl_result",
               "final_result", "anomaly_score",
               "attack_type", "threat_level"]

    output  = io.StringIO()
    writer  = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(logs)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=nids_logs.csv"},
    )





# ─────────────────────────────────────────────────────────────────────────────
#  REST API – AI Alert Analysis (Qwen)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json() or {}
    result = analyze_alert(
        attack_type = data.get("attack_type", "Unknown"),
        src_ip      = data.get("src_ip", ""),
        dst_ip      = data.get("dst_ip", ""),
        score       = float(data.get("anomaly_score", 0)),
        threat      = data.get("threat_level", "High"),
        extra       = data,
    )
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
#  REST API – GeoIP lookup
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/geoip/<ip>")
@login_required
def api_geoip(ip):
    from backend.geoip import lookup
    return jsonify(lookup(ip))


@app.route("/api/db-status")
@login_required
def api_db_status():
    status = {"connected": _db_available}
    if _db_available:
        try:
            stats = _db.get_stats()
            status.update({"total_packets": stats["total_packets"],
                           "total_anomalies": stats["total_anomalies"]})
        except Exception as e:
            status["error"] = str(e)
    else:
        status["message"] = "Copy .env.example to .env and set DB credentials"
    return jsonify(status)

# ─────────────────────────────────────────────────────────────────────────────
#  REST API – Model training (trigger re-train from UI)
# ─────────────────────────────────────────────────────────────────────────────
import threading as _threading

_train_status = {"running": False, "progress": "", "last_result": None}

@app.route("/api/train/status")
@login_required
def api_train_status():
    return jsonify(_train_status)


@app.route("/api/train", methods=["POST"])
@login_required
def api_trigger_train():
    if _train_status["running"]:
        return jsonify({"error": "Training already running"}), 409

    data     = request.get_json() or {}
    datasets = data.get("datasets", [])   # list of {type, path}
    inc_syn  = data.get("include_synthetic", True)
    max_rows = int(data.get("max_rows", 150_000))

    specs = [(d["type"], d["path"]) for d in datasets if d.get("type") and d.get("path")]

    def _do_train():
        _train_status["running"]  = True
        _train_status["progress"] = "Starting …"
        try:
            from backend.train.train_all import train_all
            _train_status["progress"] = "Loading datasets …"
            result = train_all(dataset_specs=specs, include_synthetic=inc_syn,
                               max_rows_per_ds=max_rows)
            _train_status["progress"]    = "Reloading models …"
            load_models()
            _train_status["last_result"] = {
                "n_samples":  result["n_samples"],
                "n_normal":   result["n_normal"],
                "accuracy":   result["metrics"]["accuracy"],
                "cv_f1":      result["metrics"]["cv_f1_mean"],
            }
            _train_status["progress"] = "Complete ✓"
            socketio.emit("training_done", _train_status["last_result"])
            logger.info("Re-training complete via API")
        except Exception as exc:
            _train_status["progress"] = f"ERROR: {exc}"
            logger.exception(f"Training failed: {exc}")
        finally:
            _train_status["running"] = False

    t = _threading.Thread(target=_do_train, daemon=True, name="retrain")
    t.start()
    return jsonify({"success": True, "message": "Training started in background"})

# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket events
# ─────────────────────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.debug(f"Client connected: {request.sid}")
    emit("stats_update", _build_stats())


@socketio.on("disconnect")
def on_disconnect():
    logger.debug(f"Client disconnected: {request.sid}")


@socketio.on("request_stats")
def on_request_stats():
    emit("stats_update", _build_stats())


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.min


# ─────────────────────────────────────────────────────────────────────────────
#  Entrypoint
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    start_system()
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
