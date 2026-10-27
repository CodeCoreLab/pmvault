#!/bin/bash
# 重置环境：只按监听端口精确定位 php -S 进程，避免 pgrep -f 自匹配误杀
set -u
DIR=/opt/lab/pm2.0
PORT=8099

PID=$(ss -lntpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
if [ -n "${PID:-}" ]; then
  echo "  kill 旧服务 pid=$PID"
  kill "$PID" 2>/dev/null || true
  sleep 1
else
  echo "  无旧服务"
fi

rm -f "$DIR/data/passwords.db" "$DIR"/data/backups/*.db
echo "  数据目录现状:"
ls -la "$DIR/data" "$DIR/data/backups" | sed 's/^/    /'
echo -n "  重启前用户数: "
if [ -f "$DIR/data/passwords.db" ]; then
  sqlite3 "$DIR/data/passwords.db" "select count(*) from users;"
else
  echo "无库（干净）"
fi
