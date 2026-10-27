#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""最终闭环：无网测试机（GOPROXY=off）编译 Windows 产物 → 传回 Windows 验证运行。

这是「离线可开发」假设的决定性验证：
  · 测试机无公网（实测 curl 到 goproxy.cn 不通）
  · Go 工具链来自内网 apt 镜像（go1.22.2）
  · 依赖靠 vendor 目录（41.8 MB 压缩包搬运）
"""
from __future__ import annotations

from pathlib import Path

import hashlib
import io
import os
import socket
import sys
import tarfile

import paramiko

JUMP = "example-jump-host"
TEST = "example-test-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
SRC = r"E:\WorkBuddy\2026-10-21-10-27-34\重构验证\phase-a"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\xbuild_out"


def conn(host, timeout=15):
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    c.set_missing_host_key_policy(paramiko.WarningPolicy())
    c.connect(hostname=host, port=22, username="root", key_filename=KEY,
              timeout=timeout, banner_timeout=20, auth_timeout=20,
              allow_agent=False, look_for_keys=False)
    return c


def run(cli, cmd, timeout=600, indent="    "):
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


def main() -> int:
    print("=" * 62)
    print("最终闭环：无网测试机离线编译 → Windows 验证")
    print("=" * 62)

    # 1) 取 vendor 包（上一轮已生成在跳板机）
    jump = conn(JUMP)
    local_vp = os.path.join(os.environ["TEMP"], "vendor_pack.tar.gz")
    sftp = jump.open_sftp()
    sftp.get("/tmp/vendor_pack.tar.gz", local_vp)
    sftp.close()
    print(f"[1] vendor 包 {os.path.getsize(local_vp):,} 字节")

    # 2) 推送到无网测试机
    test = conn(TEST, timeout=12)
    sftp = test.open_sftp()
    sftp.put(local_vp, "/tmp/vendor_pack.tar.gz")
    sftp.close()
    print("[2] 已推送至测试机 /tmp/vendor_pack.tar.gz")

    run(test, "rm -rf /tmp/offbuild && mkdir -p /tmp/offbuild && "
              "tar -C /tmp/offbuild -xzf /tmp/vendor_pack.tar.gz && "
              "echo \"vendor 文件数: $(find /tmp/offbuild/vendor -type f | wc -l)\"", 200)

    # 3) 把源码也推上去（不含 vendor，vendor 单独解）
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in ("bin", "dist", "dist-windows", "vendor")]
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, SRC).replace("\\", "/")
                t.add(full, arcname=rel)
    sftp = test.open_sftp()
    with sftp.open("/tmp/src_pack.tar.gz", "wb") as fh:
        fh.write(buf.getvalue())
    sftp.close()
    run(test, "tar -C /tmp/offbuild -xzf /tmp/src_pack.tar.gz && "
              "ls /tmp/offbuild | head -10", 120)

    # 4) 确认网络确实不可用
    print("\n[3] 确认测试机无公网（编译前）")
    run(test, "timeout 6 curl -sS -o /dev/null -w 'goproxy.cn=%{http_code}\\n' "
              "https://goproxy.cn 2>&1 || echo 'goproxy.cn 不可达（符合预期）'", 60)

    # 5) 断网条件下编译 Windows 产物
    print("\n[4] GOPROXY=off + vendor 编译 Windows 产物")
    run(test, "cd /tmp/offbuild && export HOME=/root GOPATH=/root/go GOCACHE=/root/.cache/go-build; "
              "GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "
              "go build -trimpath -ldflags='-s -w' -o /tmp/offbuild/vault-win-offline.exe "
              "./cmd/vaultd 2>&1 | head -10; "
              "ls -la /tmp/offbuild/vault-win-offline.exe 2>/dev/null | awk '{print \"size=\"$5}'; "
              "file -b /tmp/offbuild/vault-win-offline.exe | cut -c1-70", 900)

    # 6) 同时编译 Windows GUI（无控制台）并做多架构
    print("\n[5] 离线多架构矩阵")
    run(test, "cd /tmp/offbuild && export GOPATH=/root/go GOCACHE=/root/.cache/go-build; "
              "for t in windows/amd64 windows/arm64 linux/arm64; do "
              "os=${t%/*}; arch=${t#*/}; "
              "GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 GOOS=$os GOARCH=$arch "
              "go build -trimpath -ldflags='-s -w' -o /tmp/offbuild/x-$os-$arch ./cmd/vaultd 2>&1|head -3; "
              "printf '  %-16s %6.2f MB\\n' $os/$arch "
              "$(stat -c %s /tmp/offbuild/x-$os-$arch 2>/dev/null | awk '{print $1/1048576}'); "
              "done", 900)

    # 7) 校验哈希 + 传回 Windows
    print("\n[6] 校验并传回 Windows")
    h_remote = run(test, "sha256sum /tmp/offbuild/vault-win-offline.exe | cut -d' ' -f1", 60).strip()
    os.makedirs(OUT, exist_ok=True)
    local = os.path.join(OUT, "vault-win-offline.exe")
    sftp = test.open_sftp()
    sftp.get("/tmp/offbuild/vault-win-offline.exe", local)
    sftp.close()
    h_local = hashlib.sha256(open(local, "rb").read()).hexdigest()
    print(f"    大小 {os.path.getsize(local):,} 字节")
    print(f"    远端 {h_remote[:32]}")
    print(f"    本地 {h_local[:32]}")
    print(f"    完整性 {'一致 ✓' if h_remote == h_local else '不一致 ✗'}")
    test.close()
    jump.close()

    # 8) Windows 侧运行
    print("\n[7] Windows 本机运行离线编译产物")
    import json
    import subprocess
    import time
    import urllib.request

    work = os.path.join(OUT, "offline_run")
    os.makedirs(work, exist_ok=True)
    port = 18460
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    proc = subprocess.Popen([local, "-open=false", "-addr", f"127.0.0.1:{port}"],
                            cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = False
    for _ in range(40):
        try:
            with op.open(f"http://127.0.0.1:{port}/api/status", timeout=3) as r:
                if r.status == 200:
                    d = json.loads(r.read())
                    print(f"    ✓ 启动成功 initialized={d.get('initialized')} "
                          f"argon2={d.get('argon2_ready')}")
                    ok = True
                    break
        except Exception:  # noqa: BLE001
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.4)
    if not ok:
        try:
            out, _ = proc.communicate(timeout=3)
        except Exception:  # noqa: BLE001
            proc.kill()
            out = b""
        print("    ✗ 启动失败:", out.decode("utf-8", "replace")[:300])
    proc.terminate()

    print("\n" + "=" * 62)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
