#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把本地密码管理系统 2.0 源码上传到跳板机 /opt/lab/pm2.0（仅源码，含测试库）。"""
import io
import os
import sys
import tarfile

import paramiko
from pathlib import Path

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
SRC = r"F:\360极速浏览器X下载\密码管理系统2.0\密码管理系统2.0"
REMOTE_DIR = "/opt/lab/pm2.0"
SKIP_DIRS = {"node_modules", ".git"}
SKIP_EXT = {".zip", ".rar", ".7z"}


def build_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                if os.path.splitext(f)[1].lower() in SKIP_EXT:
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, SRC).replace("\\", "/")
                try:
                    tar.add(full, arcname=rel)
                except (OSError, PermissionError) as exc:
                    print(f"[跳过] {rel}: {exc}")
    return buf.getvalue()


def main() -> int:
    blob = build_tar()
    print(f"打包完成: {len(blob)} 字节")

    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    _in, out, _err = cli.exec_command(f"mkdir -p {REMOTE_DIR} && rm -rf {REMOTE_DIR}/*", timeout=30)
    out.read()

    sftp = cli.open_sftp()
    remote_tar = "/tmp/pm2.0.tar.gz"
    with sftp.open(remote_tar, "wb") as fh:
        fh.write(blob)
    sftp.close()

    _in, out, err = cli.exec_command(
        f"tar -C {REMOTE_DIR} -xzf {remote_tar} && find {REMOTE_DIR} -type f | wc -l && du -sh {REMOTE_DIR}",
        timeout=90,
    )
    print(out.read().decode("utf-8", "replace").strip())
    e = err.read().decode("utf-8", "replace").strip()
    if e:
        print(f"[stderr] {e[:300]}")
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
