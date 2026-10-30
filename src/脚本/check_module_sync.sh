#!/usr/bin/env bash
# 检查两个 Go module 的 internal/vault 是否保持逐字节一致。
#
# 背景：src/phase-a（vaultd 服务端）与 src/phase-edgeapp（vaultgui 桌面版）
# 当前共享同一份 internal/vault 代码，两者是**副本关系**而非共享依赖。
# 改了一处忘了另一处，两个产品的安全行为就会分叉（例如只有桌面版补了审计日志）。
#
# 详见 docs/双Module副本关系与同步约定.md
#
# 退出码：
#   0 = 全部一致
#   1 = 存在差异（CI 应失败）
#   2 = 用法/环境错误

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
A="$ROOT/src/phase-a/internal/vault"
B="$ROOT/src/phase-edgeapp/internal/vault"

if [ ! -d "$A" ] || [ ! -d "$B" ]; then
  echo "错误：找不到 internal/vault 目录（A=$A B=$B）" >&2
  exit 2
fi

# 与 phase-a 逐字节相同的 Go 文件（version.go 除外，见下方说明）
FILES="app.go crypto.go errors.go extra.go store.go vault_test.go"
# 与 phase-a 逐字节相同的前端文件
WEB_FILES="app.js index.html app.css"

failed=0

check() {
  local rel="$1"
  if [ ! -f "$A/$rel" ]; then
    echo "缺失：phase-a/internal/vault/$rel"
    failed=1
    return
  fi
  if [ ! -f "$B/$rel" ]; then
    echo "缺失：phase-edgeapp/internal/vault/$rel"
    failed=1
    return
  fi
  if diff -q "$A/$rel" "$B/$rel" >/dev/null 2>&1; then
    echo "一致：internal/vault/$rel"
  else
    echo "不一致：internal/vault/$rel"
    diff -u "$A/$rel" "$B/$rel" | head -40
    failed=1
  fi
}

echo "=== 检查 internal/vault 副本一致性 ==="
for f in $FILES; do check "$f"; done
for f in $WEB_FILES; do check "web/$f"; done

# version.go 例外：两份只有 ldflags 注释里的 module 名不同（vaultd vs vaultgui），
# 属于有意差异。这里只校验「除该行外完全相同」。
echo
echo "=== 检查 version.go（允许 module 名注释差异）==="
if [ ! -f "$A/version.go" ] || [ ! -f "$B/version.go" ]; then
  echo "缺失：version.go"
  failed=1
else
  # 去掉含 vaultd/ 与 vaultgui/ 的那一行后比较
  sed 's|vaultd/internal/vault.Version|VERSION_PLACEHOLDER|' "$A/version.go" > /tmp/.pv_a.$$ 2>/dev/null \
    && sed 's|vaultgui/internal/vault.Version|VERSION_PLACEHOLDER|' "$B/version.go" > /tmp/.pv_b.$$ 2>/dev/null
  if diff -q /tmp/.pv_a.$$ /tmp/.pv_b.$$ >/dev/null 2>&1; then
    echo "一致：internal/vault/version.go（除 module 名注释外）"
  else
    echo "不一致：internal/vault/version.go（除 module 名注释外还有差异）"
    diff -u /tmp/.pv_a.$$ /tmp/.pv_b.$$ | head -40
    failed=1
  fi
  rm -f /tmp/.pv_a.$$ /tmp/.pv_b.$$
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "结果：两个 module 的 internal/vault 副本一致 ✓"
  exit 0
fi
echo "结果：存在不一致 ✗ —— 请同步两侧后再提交（见 docs/双Module副本关系与同步约定.md）"
exit 1
