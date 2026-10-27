#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跳板机 Ubuntu 复验：重置为全新库 → 启服务 → 跑全链路测试脚本。"""
import socket
import sys
import tempfile
from pathlib import Path

import paramiko

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
DIR = "/opt/lab/pm2.0"
# 测试脚本放在系统临时目录下，避免硬编码用户路径
SCRIPT = str(Path(tempfile.gettempdir()) / "test_body.sh")


def run(cli, cmd, timeout=60):
    _in, out, err = cli.exec_command(cmd, timeout=timeout)
    try:
        body = out.read().decode("utf-8", "replace")
    except socket.timeout:
        body = "[读取超时]"
    try:
        errs = err.read().decode("utf-8", "replace")
    except socket.timeout:
        errs = ""
    if body.strip():
        print(body.rstrip())
    if errs.strip():
        print(f"[stderr] {errs.strip()[:500]}")
    return body


def main() -> int:
    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    print("### 重置（用 PID 精确 kill，避免 pkill -f 误杀自身）")
    run(cli, "for pid in $(pgrep -f 'php -S 127.0.0.1:8099'); do kill $pid 2>/dev/null; done; sleep 1; "
             f"rm -f {DIR}/data/passwords.db {DIR}/data/backups/*.db; "
             f"ls -la {DIR}/data/ {DIR}/data/backups/ | head -12")

    print("\n### 启动服务")
    run(cli, f"sh -c 'cd {DIR} && setsid nohup /usr/bin/php -S 127.0.0.1:8099 -t . "
             f">/tmp/php_srv.log 2>&1 </dev/null & exit 0'", timeout=20)
    run(cli, "sleep 2; curl -sS -o /dev/null -w 'server HTTP=%{http_code}\\n' http://127.0.0.1:8099/index.php", timeout=30)

    sftp = cli.open_sftp()
    with sftp.open("/tmp/test_pm.sh", "wb") as fh:
        fh.write(open(SCRIPT, "rb").read())
    sftp.close()

    print("\n### 全链路测试")
    run(cli, "bash /tmp/test_pm.sh 2>&1", timeout=300)
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
