-- 告警闭环:规则、事件、通知渠道。所有敏感/用户输入在应用层强类型校验后入库。

CREATE TABLE alert_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    -- 指标白名单(应用层 enum 校验):cpu_pct/mem_pct/disk_pct/swap_pct/load1/offline
    metric        TEXT NOT NULL,
    -- 比较符白名单:gt/lt(offline 忽略)
    comparator    TEXT NOT NULL DEFAULT 'gt',
    threshold     REAL NOT NULL DEFAULT 0,
    -- 连续越界多久(秒)才触发,消抖
    duration_secs INTEGER NOT NULL DEFAULT 0,
    -- NULL = 应用到所有节点;否则限定单节点
    node_id       INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_alert_rules_node ON alert_rules(node_id);

CREATE TABLE alert_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    -- firing | resolved
    state       TEXT NOT NULL,
    value       REAL NOT NULL DEFAULT 0,
    started_at  INTEGER NOT NULL,
    resolved_at INTEGER,
    message     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_alert_events_open ON alert_events(rule_id, node_id) WHERE resolved_at IS NULL;
CREATE INDEX idx_alert_events_ts ON alert_events(started_at);

CREATE TABLE notify_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 渠道类型白名单:webhook(P0);telegram/bark(P1)
    kind       TEXT NOT NULL DEFAULT 'webhook',
    name       TEXT NOT NULL,
    -- webhook: 完整 https URL;telegram: bot token;bark: 服务基址
    url        TEXT NOT NULL,
    -- 附加参数(telegram chat_id 等),JSON 或空
    extra      TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
