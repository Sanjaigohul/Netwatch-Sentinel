-- ============================================================
--  NIDS Database Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS nids_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE nids_db;

-- ─────────────────────────────────────────────────────────────
-- 1. Raw packet metadata
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS packets (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    src_ip          VARCHAR(45)  NOT NULL,
    dst_ip          VARCHAR(45)  NOT NULL,
    src_port        SMALLINT UNSIGNED DEFAULT 0,
    dst_port        SMALLINT UNSIGNED DEFAULT 0,
    protocol        VARCHAR(10)  NOT NULL DEFAULT 'UNKNOWN',
    protocol_num    TINYINT UNSIGNED DEFAULT 0,
    packet_length   MEDIUMINT UNSIGNED DEFAULT 0,
    flags           VARCHAR(20)  DEFAULT '',
    ttl             TINYINT UNSIGNED DEFAULT 0,
    INDEX idx_ts      (timestamp),
    INDEX idx_src_ip  (src_ip),
    INDEX idx_dst_ip  (dst_ip)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 2. Extracted feature vectors (stored as JSON for flexibility)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS features (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    packet_id       BIGINT UNSIGNED NOT NULL,
    feature_vector  JSON            NOT NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    FOREIGN KEY (packet_id) REFERENCES packets(id) ON DELETE CASCADE,
    INDEX idx_pkt (packet_id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 3. Detection results
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS results (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    packet_id       BIGINT UNSIGNED NOT NULL,
    timestamp       DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    src_ip          VARCHAR(45)     NOT NULL,
    dst_ip          VARCHAR(45)     NOT NULL,
    protocol        VARCHAR(10)     DEFAULT 'UNKNOWN',
    ml_result       TINYINT(1)      NOT NULL COMMENT '1=normal, -1=anomaly',
    dl_result       TINYINT(1)      NOT NULL COMMENT '1=normal, -1=anomaly',
    final_result    TINYINT(1)      NOT NULL COMMENT '1=normal, -1=anomaly',
    anomaly_score   FLOAT           DEFAULT 0.0,
    reconstruction_error FLOAT      DEFAULT 0.0,
    attack_type     VARCHAR(50)     DEFAULT 'Normal',
    threat_level    ENUM('Low','Medium','High','Critical') DEFAULT 'Low',
    is_blacklisted  TINYINT(1)      DEFAULT 0,
    FOREIGN KEY (packet_id) REFERENCES packets(id) ON DELETE CASCADE,
    INDEX idx_ts         (timestamp),
    INDEX idx_src_ip     (src_ip),
    INDEX idx_final      (final_result),
    INDEX idx_attack     (attack_type),
    INDEX idx_threat     (threat_level)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 4. IP Blacklist
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blacklist (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address  VARCHAR(45)  NOT NULL UNIQUE,
    reason      VARCHAR(255) DEFAULT '',
    added_by    VARCHAR(64)  DEFAULT 'system',
    added_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 5. IP Whitelist
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS whitelist (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address  VARCHAR(45)  NOT NULL UNIQUE,
    reason      VARCHAR(255) DEFAULT '',
    added_by    VARCHAR(64)  DEFAULT 'admin',
    added_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 6. Alert log
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    src_ip          VARCHAR(45)  NOT NULL,
    dst_ip          VARCHAR(45)  NOT NULL,
    attack_type     VARCHAR(50)  DEFAULT 'Unknown',
    threat_level    ENUM('Low','Medium','High','Critical') DEFAULT 'High',
    anomaly_score   FLOAT        DEFAULT 0.0,
    acknowledged    TINYINT(1)   DEFAULT 0,
    INDEX idx_ts    (timestamp),
    INDEX idx_src   (src_ip),
    INDEX idx_ack   (acknowledged)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 7. Seed whitelist with localhost
-- ─────────────────────────────────────────────────────────────
INSERT IGNORE INTO whitelist (ip_address, reason, added_by)
VALUES
    ('127.0.0.1',  'Localhost',      'system'),
    ('0.0.0.0',    'Default route',  'system'),
    ('::1',        'IPv6 loopback',  'system');

-- ── Add new columns if upgrading from earlier version ──────────────────────
ALTER TABLE packets ADD COLUMN bytes       INT UNSIGNED DEFAULT 0;
ALTER TABLE packets ADD COLUMN duration    FLOAT DEFAULT 0.0;
ALTER TABLE packets ADD COLUMN country     VARCHAR(64) DEFAULT '';
ALTER TABLE packets ADD COLUMN country_code VARCHAR(4) DEFAULT '';
ALTER TABLE packets ADD COLUMN isp         VARCHAR(128) DEFAULT '';
ALTER TABLE packets ADD COLUMN city        VARCHAR(64) DEFAULT '';

ALTER TABLE results ADD COLUMN bytes       INT UNSIGNED DEFAULT 0;
ALTER TABLE results ADD COLUMN duration    FLOAT DEFAULT 0.0;
ALTER TABLE results ADD COLUMN country     VARCHAR(64) DEFAULT '';
ALTER TABLE results ADD COLUMN isp         VARCHAR(128) DEFAULT '';

ALTER TABLE blacklist ADD COLUMN country   VARCHAR(64) DEFAULT '';
ALTER TABLE blacklist ADD COLUMN isp       VARCHAR(128) DEFAULT '';
ALTER TABLE whitelist ADD COLUMN country   VARCHAR(64) DEFAULT '';
ALTER TABLE whitelist ADD COLUMN isp       VARCHAR(128) DEFAULT '';
