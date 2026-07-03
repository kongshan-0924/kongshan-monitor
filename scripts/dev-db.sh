#!/bin/sh
# 生成 sqlx 编译期校验所需的开发数据库(与迁移保持一致)。
# 同时生成到 workspace 根与 crates/server 下,兼容不同的相对路径解析基准。
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for DB_DIR in "$ROOT/.dev" "$ROOT/crates/server/.dev"; do
  mkdir -p "$DB_DIR"
  rm -f "$DB_DIR/dev.db"
  for f in "$ROOT"/crates/server/migrations/*.sql; do
    sqlite3 "$DB_DIR/dev.db" < "$f"
  done
done
echo "dev db ready"
