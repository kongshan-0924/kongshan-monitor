-- 记录 agent 最近一次建立 WS 连接时的来源 IP(此前只临时写日志,不落库)。
ALTER TABLE nodes ADD COLUMN last_ip TEXT NOT NULL DEFAULT '';
