-- P1 告警增强:严重度分级、按严重度路由渠道、维护窗口静默、重复提醒。
ALTER TABLE alert_rules ADD COLUMN severity TEXT NOT NULL DEFAULT 'warning';
-- 渠道只接收 >= 自身 min_severity 的告警(info < warning < critical)
ALTER TABLE notify_channels ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'info';
-- 事件最近一次外发通知时刻,用于重复提醒(re-notify)节流
ALTER TABLE alert_events ADD COLUMN last_notified_at INTEGER;

-- 维护窗口/静默:命中窗口的 (节点×规则) 在窗口内不外发通知(仍记录事件/推 UI)
CREATE TABLE alert_silences (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER REFERENCES nodes(id) ON DELETE CASCADE,      -- NULL=所有节点
    rule_id    INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE, -- NULL=所有规则
    start_ts   INTEGER NOT NULL,
    end_ts     INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_silences_window ON alert_silences(end_ts);
