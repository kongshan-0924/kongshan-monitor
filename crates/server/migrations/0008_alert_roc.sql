-- 变化率(roc)告警条件:comparator='roc' 时,窗口(秒)内的绝对变化量 >= threshold 即触发。
ALTER TABLE alert_rules ADD COLUMN roc_window_secs INTEGER NOT NULL DEFAULT 0;
