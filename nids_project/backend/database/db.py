"""
database/db.py – MySQL connection pool + helper functions
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import json
import logging
from contextlib import contextmanager
from datetime import datetime

import mysql.connector
from mysql.connector import pooling

from config import Config

logger = logging.getLogger(__name__)

# ─── Connection pool ─────────────────────────────────────────────────────────

_pool: pooling.MySQLConnectionPool | None = None


def get_pool() -> pooling.MySQLConnectionPool:
    global _pool
    if _pool is None:
        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name="nids_pool",
                pool_size=10,
                pool_reset_session=True,
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                database=Config.DB_NAME,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                autocommit=False,
                charset="utf8mb4",
                collation="utf8mb4_unicode_ci",
            )
            logger.info("MySQL connection pool created (size=10)")
        except Exception as exc:
            logger.error(f"Cannot create MySQL pool: {exc}")
            raise
    return _pool


@contextmanager
def get_conn():
    """Context manager – yields (conn, cursor), commits on exit, rolls back on error."""
    pool = get_pool()
    conn = pool.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        yield conn, cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def init_db():
    """Execute schema.sql to create tables if they don't exist."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        sql = f.read()

    # Split on semicolons, skip empty statements
    statements = [s.strip() for s in sql.split(";") if s.strip()]

    # Use a raw connector (not pooled) for schema ops
    try:
        conn = mysql.connector.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            autocommit=True,
            charset="utf8mb4",
        )
        cur = conn.cursor()
        for stmt in statements:
            try:
                cur.execute(stmt)
            except mysql.connector.Error as e:
                if e.errno not in (1007, 1050, 1060, 1062):   # already exists / duplicate
                    logger.warning(f"Schema stmt warning: {e}")
        cur.close()
        conn.close()
        logger.info("Database schema initialized successfully")
    except Exception as exc:
        logger.error(f"DB init failed: {exc}")
        raise


# ─── Packet helpers ──────────────────────────────────────────────────────────

def insert_packet(pkt: dict) -> int:
    sql = """
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port,
             protocol, protocol_num, packet_length, flags, ttl)
        VALUES
            (%(timestamp)s, %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s,
             %(protocol)s, %(protocol_num)s, %(packet_length)s, %(flags)s, %(ttl)s)
    """
    with get_conn() as (conn, cur):
        cur.execute(sql, pkt)
        return cur.lastrowid


def insert_features(packet_id: int, feature_vector):
    sql = """
        INSERT INTO features (packet_id, feature_vector)
        VALUES (%s, %s)
    """
    fv_json = json.dumps(feature_vector.tolist() if hasattr(feature_vector, "tolist")
                         else list(feature_vector))
    with get_conn() as (conn, cur):
        cur.execute(sql, (packet_id, fv_json))


def insert_result(res: dict) -> int:
    sql = """
        INSERT INTO results
            (packet_id, timestamp, src_ip, dst_ip, protocol,
             ml_result, dl_result, final_result,
             anomaly_score, reconstruction_error,
             attack_type, threat_level, is_blacklisted)
        VALUES
            (%(packet_id)s, %(timestamp)s, %(src_ip)s, %(dst_ip)s, %(protocol)s,
             %(ml_result)s, %(dl_result)s, %(final_result)s,
             %(anomaly_score)s, %(reconstruction_error)s,
             %(attack_type)s, %(threat_level)s, %(is_blacklisted)s)
    """
    with get_conn() as (conn, cur):
        cur.execute(sql, res)
        return cur.lastrowid


def insert_alert(alert: dict) -> int:
    sql = """
        INSERT INTO alerts
            (timestamp, src_ip, dst_ip, attack_type, threat_level, anomaly_score)
        VALUES
            (%(timestamp)s, %(src_ip)s, %(dst_ip)s, %(attack_type)s,
             %(threat_level)s, %(anomaly_score)s)
    """
    with get_conn() as (conn, cur):
        cur.execute(sql, alert)
        return cur.lastrowid


# ─── Query helpers ───────────────────────────────────────────────────────────

def get_logs(page=1, per_page=50, search=None, time_range=None,
             threat_level=None, final_result=None):
    offset = (page - 1) * per_page
    conditions = []
    params = []

    if search:
        conditions.append("(r.src_ip LIKE %s OR r.dst_ip LIKE %s OR r.attack_type LIKE %s)")
        params += [f"%{search}%"] * 3
    if time_range:
        conditions.append("r.timestamp >= %s")
        params.append(time_range)
    if threat_level:
        conditions.append("r.threat_level = %s")
        params.append(threat_level)
    if final_result is not None:
        conditions.append("r.final_result = %s")
        params.append(final_result)

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    count_sql = f"SELECT COUNT(*) AS cnt FROM results r {where}"
    data_sql  = f"""
        SELECT r.id, r.timestamp, r.src_ip, r.dst_ip, r.protocol,
               r.ml_result, r.dl_result, r.final_result,
               r.anomaly_score, r.reconstruction_error,
               r.attack_type, r.threat_level, r.is_blacklisted
        FROM results r {where}
        ORDER BY r.timestamp DESC
        LIMIT %s OFFSET %s
    """
    with get_conn() as (conn, cur):
        cur.execute(count_sql, params)
        total = cur.fetchone()["cnt"]
        cur.execute(data_sql, params + [per_page, offset])
        rows = cur.fetchall()

    # Serialize datetime
    for row in rows:
        if isinstance(row.get("timestamp"), datetime):
            row["timestamp"] = row["timestamp"].isoformat()
    return rows, total


def get_recent_alerts(limit=20):
    sql = """
        SELECT id, timestamp, src_ip, dst_ip, attack_type, threat_level, anomaly_score
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT %s
    """
    with get_conn() as (conn, cur):
        cur.execute(sql, (limit,))
        rows = cur.fetchall()
    for row in rows:
        if isinstance(row.get("timestamp"), datetime):
            row["timestamp"] = row["timestamp"].isoformat()
    return rows


def get_stats():
    with get_conn() as (conn, cur):
        cur.execute("SELECT COUNT(*) AS cnt FROM packets")
        total_packets = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) AS cnt FROM results WHERE final_result = -1")
        total_anomalies = cur.fetchone()["cnt"]

        cur.execute("""
            SELECT COUNT(*) AS cnt FROM results
            WHERE final_result = -1
              AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        """)
        active_threats = cur.fetchone()["cnt"]

        cur.execute("""
            SELECT attack_type, COUNT(*) AS cnt
            FROM results
            WHERE final_result = -1
            GROUP BY attack_type
            ORDER BY cnt DESC
        """)
        attack_dist = {r["attack_type"]: r["cnt"] for r in cur.fetchall()}

        cur.execute("""
            SELECT src_ip, COUNT(*) AS cnt
            FROM results
            WHERE final_result = -1
            GROUP BY src_ip
            ORDER BY cnt DESC
            LIMIT 10
        """)
        top_attackers = cur.fetchall()

        cur.execute("""
            SELECT threat_level, COUNT(*) AS cnt
            FROM results
            WHERE final_result = -1
            GROUP BY threat_level
        """)
        threat_dist = {r["threat_level"]: r["cnt"] for r in cur.fetchall()}

    return {
        "total_packets":  total_packets,
        "total_anomalies": total_anomalies,
        "active_threats":  active_threats,
        "attack_distribution": attack_dist,
        "top_attackers":  top_attackers,
        "threat_distribution": threat_dist,
    }


# ─── Blacklist / Whitelist ───────────────────────────────────────────────────

def get_blacklist():
    with get_conn() as (conn, cur):
        cur.execute("SELECT ip_address, reason, added_by, added_at FROM blacklist ORDER BY added_at DESC")
        return cur.fetchall()


def add_to_blacklist(ip: str, reason: str = "", added_by: str = "admin"):
    with get_conn() as (conn, cur):
        cur.execute(
            "INSERT IGNORE INTO blacklist (ip_address, reason, added_by) VALUES (%s, %s, %s)",
            (ip, reason, added_by)
        )


def remove_from_blacklist(ip: str):
    with get_conn() as (conn, cur):
        cur.execute("DELETE FROM blacklist WHERE ip_address = %s", (ip,))


def get_whitelist():
    with get_conn() as (conn, cur):
        cur.execute("SELECT ip_address, reason, added_by, added_at FROM whitelist ORDER BY added_at DESC")
        return cur.fetchall()


def add_to_whitelist(ip: str, reason: str = "", added_by: str = "admin"):
    with get_conn() as (conn, cur):
        cur.execute(
            "INSERT IGNORE INTO whitelist (ip_address, reason, added_by) VALUES (%s, %s, %s)",
            (ip, reason, added_by)
        )


def remove_from_whitelist(ip: str):
    with get_conn() as (conn, cur):
        cur.execute("DELETE FROM whitelist WHERE ip_address = %s", (ip,))


def is_blacklisted(ip: str) -> bool:
    with get_conn() as (conn, cur):
        cur.execute("SELECT 1 FROM blacklist WHERE ip_address = %s LIMIT 1", (ip,))
        return cur.fetchone() is not None


def is_whitelisted(ip: str) -> bool:
    with get_conn() as (conn, cur):
        cur.execute("SELECT 1 FROM whitelist WHERE ip_address = %s LIMIT 1", (ip,))
        return cur.fetchone() is not None
