#!/bin/sh
# 交叉编译发布产物(musl 全静态)。产物输出到 dist/,附 SHA-256 清单。
# 依赖:rustup targets + zig + cargo-zigbuild(macOS: brew install zig cargo-zigbuild)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
sh scripts/dev-db.sh >/dev/null

TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"
mkdir -p dist
for T in $TARGETS; do
  echo "==> building $T"
  cargo zigbuild --release --target "$T" -p outpost-agent -p outpost-server
  cp "target/$T/release/outpost-agent" "dist/outpost-agent-$T"
  cp "target/$T/release/outpost-server" "dist/outpost-server-$T"
done
(cd dist && shasum -a 256 outpost-* > SHA256SUMS)
echo "==> dist/"
ls -la dist/
cat dist/SHA256SUMS
