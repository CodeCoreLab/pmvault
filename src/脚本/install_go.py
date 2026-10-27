#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""在跳板机安装 Go 工具链（仅解压到 /opt，不改系统默认路径）。幂等。"""
import sys

import paramiko
from pathlib import Path

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
GO_VER = "1.23.4"

STEPS = [
    ("下载 go", f"test -x /opt/go/bin/go && echo 'ALREADY' || "
                f"(cd /tmp && curl -sS -L --max-time 240 -o go.tgz "
                f"https://dl.google.com/go/go{GO_VER}.linux-amd64.tar.gz && ls -la go.tgz)"),
    ("解压", f"test -x /opt/go/bin/go && echo 'SKIP' || (rm -rf /opt/go && tar -C /opt -xzf /tmp/go.tgz && echo EXTRACTED)"),
    ("版本", "/opt/go/bin/go version"),
]


def main() -> int:
    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)
    for label, cmd in STEPS:
        _in, out, err = cli.exec_command(cmd, timeout=300)
        body = out.read().decode("utf-8", "replace").strip()
        errs = err.read().decode("utf-8", "replace").strip()
        print(f"--- {label} ---\n{body or '(空)'}")
        if errs:
            print(f"[stderr] {errs[:400]}")
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
