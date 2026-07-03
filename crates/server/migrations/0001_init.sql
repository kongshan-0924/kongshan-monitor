-- outpost 初始表结构。所有敏感值(会话/注册密钥/agent token)只存 SHA-256 哈希。
CREATE TABLE users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    pass_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE nodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    grp           TEXT NOT NULL DEFAULT '',
    token_hash    TEXT UNIQUE,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    registered_at INTEGER,
    last_seen     INTEGER,
    hostname      TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    kernel        TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    cores         INTEGER NOT NULL DEFAULT 0,
    mem_total     INTEGER NOT NULL DEFAULT 0,
    agent_version TEXT NOT NULL DEFAULT ''
);

CREATE TABLE register_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE CASCADE,
    key_hash   TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE metrics (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    ts            INTEGER NOT NULL,
    cpu_pct       REAL NOT NULL,
    load1         REAL NOT NULL,
    load5         REAL NOT NULL,
    load15        REAL NOT NULL,
    mem_total     INTEGER NOT NULL,
    mem_used      INTEGER NOT NULL,
    mem_available INTEGER NOT NULL,
    swap_total    INTEGER NOT NULL,
    swap_used     INTEGER NOT NULL,
    disk_total    INTEGER NOT NULL,
    disk_used     INTEGER NOT NULL,
    disk_read_bps  INTEGER NOT NULL,
    disk_write_bps INTEGER NOT NULL,
    net_rx_bps    INTEGER NOT NULL,
    net_tx_bps    INTEGER NOT NULL,
    uptime_secs   INTEGER NOT NULL,
    procs         INTEGER NOT NULL,
    detail        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_metrics_node_ts ON metrics(node_id, ts);

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    ip       TEXT NOT NULL DEFAULT '',
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_ts ON audit_log(ts);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
