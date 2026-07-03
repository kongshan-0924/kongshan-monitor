-- 两步验证(TOTP)与一次性恢复码。totp_secret 为 base32(仅在启用后有效)。
ALTER TABLE users ADD COLUMN totp_secret  TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   INTEGER
);
CREATE INDEX idx_recovery_user ON recovery_codes(user_id);
