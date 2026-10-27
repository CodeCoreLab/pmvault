#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""实测真实项目（密码管理器 Go 版）在 Ubuntu 交叉编译为 Windows GUI 产物。

这是可行性验证的关键一环：项目依赖 modernc.org/sqlite（纯 Go，无 CGO），
理论上可零依赖交叉编译；此处实测确认并产出可直接运行的 Windows 程序。
"""
from __future__ import annotations

from pathlib import Path

import io
import os
import socket
import sys
import tarfile

import paramiko

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
SRC = r"E:\WorkBuddy\2026-10-21-10-27-34\重构验证\phase-a"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\xbuild_out"
GO_ENV = ("export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache "
          "GOPROXY=https://goproxy.cn,direct GOFLAGS=-mod=mod;")


def run(cli, cmd, timeout=500, indent="    "):
    _in, out, err = cli.exec_command(cmd, timeout=timeout)
    try:
        body = out.read().decode("utf-8", "replace")
    except socket.timeout:
        body = "[读取超时]"
    try:
        errs = err.read().decode("utf-8", "replace")
    except socket.timeout:
        errs = ""
    for line in (body or "").strip().splitlines():
        print(indent + line)
    if errs.strip():
        for line in errs.strip().splitlines()[:8]:
            print(indent + "[err] " + line)
    return body


def pack() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in ("bin", "dist", "dist-windows")]
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, SRC).replace("\\", "/")
                t.add(full, arcname=rel)
    return buf.getvalue()


def main() -> int:
    print("=" * 62)
    print("真实项目：Ubuntu 交叉编译 Windows 版（密码管理器）")
    print("=" * 62)

    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    blob = pack()
    sftp = cli.open_sftp()
    with sftp.open("/tmp/proj.tar.gz", "wb") as fh:
        fh.write(blob)
    sftp.close()
    print(f"  源码包 {len(blob):,} 字节")

    run(cli, "rm -rf /tmp/xproj && mkdir -p /tmp/xproj && "
             "tar -C /tmp/xproj -xzf /tmp/proj.tar.gz && echo unpacked", 90)

    print("\n[1] go mod tidy（联网拉依赖）")
    run(cli, GO_ENV + " cd /tmp/xproj && go mod tidy 2>&1 | tail -4", 500)

    print("\n[2] 交叉编译 Windows 版（无控制台 GUI / 静态）")
    run(cli, GO_ENV + " cd /tmp/xproj && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "
         "go build -trimpath -ldflags='-s -w -H windowsgui -X vaultd.internal/x=1' "
         "-o /tmp/xproj/vaultd-cross.exe ./cmd/vaultd 2>&1 | head -10; "
         "ls -la /tmp/xproj/vaultd-cross.exe 2>/dev/null | awk '{print \"size=\"$5}'; "
         "file -b /tmp/xproj/vaultd-cross.exe | cut -c1-80", 500)

    print("\n[3] 校验是否静态链接（Windows 侧无需任何运行库）")
    run(cli, "cd /tmp/xproj && (x86_64-w64-mingw32-objdump -p vaultd-cross.exe 2>/dev/null "
             "| grep -i 'DLL Name' | sort -u | head -20) || echo 'objdump 不可用'", 90)

    print("\n[4] 取回 Windows 并实测运行")
    os.makedirs(OUT, exist_ok=True)
    local = os.path.join(OUT, "vaultd-cross.exe")
    sftp = cli.open_sftp()
    sftp.get("/tmp/xproj/vaultd-cross.exe", local)
    sftp.close()
    size = os.path.getsize(local)
    print(f"    已取回 {size:,} 字节")

    import hashlib
    lh = hashlib.sha256(open(local, "rb").read()).hexdigest()
    rh = run(cli, "sha256sum /tmp/xproj/vaultd-cross.exe | cut -d' ' -f1", 30).strip()
    print(f"    本地 sha256: {lh[:32]}")
    print(f"    远端 sha256: {rh[:32]}")
    print(f"    传输完整性: {'一致 ✓' if lh == rh else '不一致 ✗'}")

    cli.close()

    # Windows 侧跑一遍
    print("\n[5] Windows 本机启动交叉编译产物（端口探测）")
    import json
    import subprocess
    import time
    import urllib.request

    work = os.path.join(OUT, "run")
    os.makedirs(work, exist_ok=True)
    port = 18450
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    proc = subprocess.Popen([local, "-open=false", "-addr", f"127.0.0.1:{port}"],
                            cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = False
    for _ in range(40):
        try:
            with op.open(f"http://127.0.0.1:{port}/api/status", timeout=3) as r:
                if r.status == 200:
                    d = json.loads(r.read())
                    ok = True
                    print(f"    ✓ 服务就绪: initialized={d.get('initialized')}, "
                          f"argon2={d.get('argon2_ready')}")
                    break
        except Exception:  # noqa: BLE001
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.4)
    if not ok:
        print("    ✗ 未能启动")
        try:
            out, _ = proc.communicate(timeout=3)
        except Exception:  # noqa: BLE001
            proc.kill()
            out = b""
        print("    输出:", out.decode("utf-8", "replace")[:400])
    proc.terminate()
    print("\n" + "=" * 62)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
