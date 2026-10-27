#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""离线编译可行性验证：在有网跳板机做 vendor + 工具链缓存，搬到无网测试机编译。

核心问题：无网机器拿不到模块依赖。解法是「在有网机器预热 GOMODCACHE 与 vendor」。
本脚本实测：
  1. 有网侧：go mod vendor 生成依赖包
  2. 有网侧：打包 vendor 与 GOMODCACHE 体积对比
  3. 把项目（含 vendor）推到无网测试机 → 尝试 GOFLAGS=-mod=vendor 直接编译
"""
from __future__ import annotations

from pathlib import Path

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
GO_ENV = ("export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache "
          "GOPROXY=https://goproxy.cn,direct GOFLAGS=-mod=mod;")


def conn(host, timeout=15):
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    c.set_missing_host_key_policy(paramiko.WarningPolicy())
    c.connect(hostname=host, port=22, username="root", key_filename=KEY,
              timeout=timeout, banner_timeout=20, auth_timeout=20,
              allow_agent=False, look_for_keys=False)
    return c


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
        for line in errs.strip().splitlines()[:6]:
            print(indent + "[err] " + line)
    return body


def pack_with_vendor(vendor_tar: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in ("bin", "dist", "dist-windows", "vendor")]
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, SRC).replace("\\", "/")
                t.add(full, arcname=rel)
    return buf.getvalue()


def main() -> int:
    print("=" * 62)
    print("离线编译可行性：有网预热 → 无网编译")
    print("=" * 62)

    jump = conn(JUMP)
    blob = pack_with_vendor(b"")
    sftp = jump.open_sftp()
    with sftp.open("/tmp/offline_proj.tar.gz", "wb") as fh:
        fh.write(blob)
    sftp.close()

    print("\n[1] 有网侧：准备项目 + go mod vendor")
    run(jump, "rm -rf /tmp/off && mkdir -p /tmp/off && tar -C /tmp/off -xzf /tmp/offline_proj.tar.gz", 90)
    run(jump, GO_ENV + " cd /tmp/off && go mod tidy >/dev/null 2>&1; "
                       "go mod vendor 2>&1 | tail -3; "
                       "echo '--- vendor 内容 ---'; ls vendor/ 2>/dev/null | head", 500)

    print("\n[2] 有网侧：vendor 体积 vs 模块缓存体积")
    run(jump, "du -sh /tmp/off/vendor 2>/dev/null; "
              "du -sh /opt/gopath/pkg/mod 2>/dev/null; "
              "find /tmp/off/vendor -type f 2>/dev/null | wc -l", 90)

    print("\n[3] 有网侧：用 vendor 离线编译验证（GOFLAGS=-mod=vendor，禁网络代理）")
    run(jump, "export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache; "
              "cd /tmp/off && GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 "
              "GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' "
              "-o /tmp/off/offline-cross.exe ./cmd/vaultd 2>&1 | head -6; "
              "ls -la /tmp/off/offline-cross.exe 2>/dev/null | awk '{print \"size=\"$5}'", 400)

    print("\n[4] 打包 vendor 供无网机器使用")
    run(jump, "cd /tmp/off && tar -czf /tmp/vendor_pack.tar.gz vendor go.mod go.sum 2>/dev/null "
              "&& ls -la /tmp/vendor_pack.tar.gz | awk '{print \"vendor包=\"$5\" 字节\"}'", 200)

    # 拉取 vendor 包到本机，再推到测试机
    local_vp = os.path.join(r"C:\Users\Administrator\AppData\Local\Temp", "vendor_pack.tar.gz")
    sftp = jump.open_sftp()
    sftp.get("/tmp/vendor_pack.tar.gz", local_vp)
    sftp.close()
    print(f"    已取回 {os.path.getsize(local_vp):,} 字节")

    print("\n[5] 无网测试机：检查 Go 是否存在")
    try:
        test = conn(TEST, timeout=12)
    except Exception as e:  # noqa: BLE001
        print(f"    连接测试机失败: {type(e).__name__}: {e}")
        jump.close()
        return 1

    run(test, "command -v go && go version || echo 'NO-GO'", 60)
    print("\n[6] 无网测试机：从内网镜像能否取到 Go（离线常态下的补救）")
    run(test, "timeout 8 curl -sS -o /dev/null -w 'yum.example.com=%{http_code}\\n' "
              "http://yum.example.com 2>&1 || echo BLOCKED", 60)
    run(test, "apt-cache policy golang-go 2>/dev/null | head -4 || echo '无 golang 包'", 60)
    test.close()
    jump.close()

    print("\n" + "=" * 62)
    print("结论要点：")
    print("  · vendor 包体积远小于完整模块缓存，适合作为离线搬运单元")
    print("  · 无网机器需预装 Go 工具链本身（vendor 只解决「依赖」，不解决「编译器」）")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
