-- 轻量 RBAC:users 加角色列。admin=完全管理;viewer=只读观察者(所有写端点拒绝)。
-- 既有账号一律为 admin(向后兼容,不改变当前行为)。
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
