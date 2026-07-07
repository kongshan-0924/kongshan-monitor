-- 服务器列表手动拖拽排序:默认按 id 顺序(新节点排最后)。
ALTER TABLE nodes ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;
UPDATE nodes SET sort_order = id;
