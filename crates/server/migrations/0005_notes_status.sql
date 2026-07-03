-- 节点备注 + 公开状态页设置(slug 存于 settings 表,默认关闭)。
ALTER TABLE nodes ADD COLUMN note TEXT NOT NULL DEFAULT '';
