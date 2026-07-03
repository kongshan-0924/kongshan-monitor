-- 只读 API Token:供外部系统(监控拉取/导出/状态页)只读访问。仅存 SHA-256。
CREATE TABLE api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used  INTEGER
);
