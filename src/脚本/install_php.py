#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跳板机 PHP 运行环境搭建：apt 安装 php-cli + sqlite/openssl/sodium 扩展。幂等。"""
import sys

import paramiko
from pathlib import Path

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")

STEPS = [
    ("已装检测", "php -v 2>&1 | head -1 || echo NO-PHP"),
    ("apt 安装", "DEBIAN_FRONTEND=noninteractive apt-get -qq install -y php-cli php-sqlite3 php-mbstring 2>&1 | tail -6"),
    ("版本", "php -v 2>&1 | head -2"),
    ("扩展核对", "php -m 2>/dev/null | grep -Ei '^(openssl|pdo_sqlite|sqlite3|sodium|mbstring)$' | tr '\\n' ' '; echo"),
]


def main() -> int:
    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)
    for label, cmd in STEPS:
        _in, out, err = cli.exec_command(cmd, timeout=420)
        body = out.read().decode("utf-8", "replace").strip()
        errs = err.read().decode("utf-8", "replace").strip()
        print(f"--- {label} ---\n{body or '(空)'}")
        if errs:
            print(f"[stderr] {errs[:300]}")
        print()
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
