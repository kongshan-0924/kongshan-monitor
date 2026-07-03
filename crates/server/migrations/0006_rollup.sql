-- 历史指标小时级聚合(降采样):长时间范围查询走此表,避免对原始 metrics 表
-- 全量扫描聚合;原始表按 retention_days 清理后,聚合表仍可长期保留低分辨率历史。
CREATE TABLE metrics_rollup (
    node_id        INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hour_ts        INTEGER NOT NULL,          -- 桶起点(整点 Unix 秒 = ts/3600*3600)
    samples        INTEGER NOT NULL,          -- 该桶原始点数
    cpu_avg        REAL    NOT NULL,
    cpu_max        REAL    NOT NULL,
    mem_used_avg   REAL    NOT NULL,
    mem_total_max  INTEGER NOT NULL,
    swap_used_avg  REAL    NOT NULL,
    disk_used_avg  REAL    NOT NULL,
    disk_total_max INTEGER NOT NULL,
    net_rx_avg     REAL    NOT NULL,
    net_tx_avg     REAL    NOT NULL,
    disk_read_avg  REAL    NOT NULL,
    disk_write_avg REAL    NOT NULL,
    load1_avg      REAL    NOT NULL,
    PRIMARY KEY (node_id, hour_ts)
);
CREATE INDEX idx_rollup_ts ON metrics_rollup(hour_ts);
