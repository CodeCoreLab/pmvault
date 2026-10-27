#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把 Go 原型上传到跳板机、拉依赖、编译并执行互通验证。"""
import socket
import sys
import tempfile
from pathlib import Path

import paramiko

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
GOPATH_ENV = "export PATH=/opt/go/bin:$PATH; export GOPATH=/opt/gopath; export GOCACHE=/opt/gocache; export GOPROXY=https://goproxy.cn,direct; export GOFLAGS=-mod=mod;"


def main() -> int:
    # 本地待上传的原型文件放在系统临时目录下，避免硬编码用户路径
    local_root = Path(tempfile.gettempdir()) / "goproto"
    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    sftp = cli.open_sftp()
    cli.exec_command("mkdir -p /opt/lab/goproto")[1].read()
    for local, remote in [
        (str(local_root / "main.go"), "/opt/lab/goproto/main.go"),
    ]:
        with sftp.open(remote, "wb") as fh:
            fh.write(open(local, "rb").read())
    sftp.close()

    steps = [
        ("init module", f"{GOPATH_ENV} cd /opt/lab/goproto && go mod init vaultproto 2>&1 | tail -2"),
        ("go mod tidy", f"{GOPATH_ENV} cd /opt/lab/goproto && go mod tidy 2>&1 | tail -10"),
        ("build", f"{GOPATH_ENV} cd /opt/lab/goproto && go build -trimpath -ldflags='-s -w' -o vault . 2>&1 | tail -10 && ls -la vault"),
    ]
    for label, cmd in steps:
        _in, out, err = cli.exec_command(cmd, timeout=300)
        try:
            body = out.read().decode("utf-8", "replace")
        except socket.timeout:
            body = "[timeout]"
        print(f"--- {label} ---\n{body.strip() or '(空)'}\n")

    # 取 PHP 侧测试数据
    q = ("sqlite3 /opt/lab/pm2.0/data/passwords.db \"select master_key_salt from users;\" ; "
         "sqlite3 /opt/lab/pm2.0/data/passwords.db \"select cipher from passwords limit 1;\"")
    _in, out, _e = cli.exec_command(q, timeout=30)
    lines = [x.strip() for x in out.read().decode("utf-8", "replace").splitlines() if x.strip()]
    if len(lines) < 2:
        print("无法取到 PHP 测试数据，先跑 /tmp/mkdata.sh")
        cli.close()
        return 1
    salt, cipher = lines[0], lines[1]
    print(f"取自 PHP 库: salt={salt} cipher={cipher[:32]}...\n")

    run = (f"{GOPATH_ENV} cd /opt/lab/goproto && ./vault -salt '{salt}' -pw 'Master5678!xyz' -cipher '{cipher}' 2>&1")
    _in, out, err = cli.exec_command(run, timeout=120)
    try:
        print("=== Go 原型输出 ===")
        print(out.read().decode("utf-8", "replace").strip())
    except socket.timeout:
        print("[timeout]")
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
