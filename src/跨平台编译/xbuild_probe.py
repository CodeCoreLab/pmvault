#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跨平台编译可行性实测：Ubuntu 跳板机交叉编译 Windows 产物 → 传回 Windows → 验证。

验证三种技术路线的交叉编译：
  1. Go  from Linux → Windows（CGO_ENABLED=0，纯 Go）
  2. Go  from Linux → Windows（CGO_ENABLED=1 + mingw，含 sqlite cgo 场景对照）
  3. Rust from Linux → Windows（gnu target，需 mingw）
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

HOST = "example-jump-host"
KEY = str(Path.home() / ".ssh" / "id_workbuddy")
LOCAL_OUT = r"C:\Users\Administrator\AppData\Local\Temp\xbuild_out"

GO_ENV = ("export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache "
          "GOPROXY=https://goproxy.cn,direct GOFLAGS=-mod=mod;")
RUST_ENV = ("export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH; "
            "export RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup;")


def run(cli, cmd, timeout=400, label=""):
    _in, out, err = cli.exec_command(cmd, timeout=timeout)
    try:
        body = out.read().decode("utf-8", "replace")
    except socket.timeout:
        body = "[读取超时]"
    try:
        errs = err.read().decode("utf-8", "replace")
    except socket.timeout:
        errs = ""
    if label:
        print(f"  {label}")
    for line in (body or "").strip().splitlines():
        print(f"    {line}")
    if errs.strip():
        for line in errs.strip().splitlines()[:6]:
            print(f"    [err] {line}")
    return body


def main() -> int:
    print("=" * 62)
    print("跨平台编译可行性实测")
    print("=" * 62)

    cli = paramiko.SSHClient()
    cli.load_system_host_keys()
    cli.set_missing_host_key_policy(paramiko.WarningPolicy())
    cli.connect(hostname=HOST, port=22, username="root", key_filename=KEY,
                timeout=15, banner_timeout=20, auth_timeout=20,
                allow_agent=False, look_for_keys=False)

    # ---------- 准备最小 Go 工程 ----------
    src = '''
package main

import (
\t"fmt"
\t"runtime"
)

func main() {
\tfmt.Printf("OS=%s ARCH=%s\\n", runtime.GOOS, runtime.GOARCH)
}
'''
    run(cli, "rm -rf /tmp/xb && mkdir -p /tmp/xb/goapp && "
             "printf '%s' '" + src.replace("'", "'\\''") + "' > /tmp/xb/goapp/main.go && "
             "cd /tmp/xb/goapp && " + GO_ENV + " go mod init xbapp 2>&1 | tail -2", 120, "准备 Go 工程")

    print("\n[1] Go 交叉编译 → Windows（纯 Go / 零依赖）")
    run(cli, GO_ENV + " cd /tmp/xb/goapp && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "
         "go build -trimpath -ldflags='-s -w' -o /tmp/xb/a-pure.exe . 2>&1 | head -5; "
         "ls -la /tmp/xb/a-pure.exe 2>/dev/null | awk '{print \"size=\"$5}'; "
         "file /tmp/xb/a-pure.exe | cut -c1-95", 240)

    print("\n[2] Go 交叉编译 → Windows（含 CGO，验证 mingw 链路）")
    run(cli, GO_ENV + " cd /tmp/xb/goapp && "
         "CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1 "
         "GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' "
         "-o /tmp/xb/b-cgo.exe . 2>&1 | head -8; "
         "ls -la /tmp/xb/b-cgo.exe 2>/dev/null | awk '{print \"size=\"$5}'", 240)

    print("\n[3] Go 交叉编译 → 三平台矩阵")
    run(cli, GO_ENV + " cd /tmp/xb/goapp && "
         "for t in windows/amd64 windows/arm64 linux/amd64 linux/arm64; do "
         "os=${t%/*}; arch=${t#*/}; "
         "CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags='-s -w' "
         "-o /tmp/xb/m-$os-$arch . && "
         "printf '  %-16s %8.2f MB\\n' $os/$arch $(stat -c %s /tmp/xb/m-$os-$arch | awk '{print $1/1048576}'); "
         "done 2>&1 | head -10", 300)

    print("\n[4] Rust 交叉编译 → Windows（验证 rustup target）")
    run(cli, RUST_ENV + " rustup target list --installed 2>&1 | head -5", 90, "已装 target")
    run(cli, RUST_ENV + " rustup target add x86_64-pc-windows-gnu 2>&1 | tail -4", 400, "安装 gnu target")
    run(cli, "mkdir -p /tmp/xb/rsapp/src && cd /tmp/xb/rsapp && "
             "printf '[package]\\nname=\"rsapp\"\\nversion=\"0.1.0\"\\nedition=\"2021\"\\n' > Cargo.toml && "
             "echo 'fn main(){ println!(\"OS={}\", std::env::consts::OS); }' > src/main.rs && "
             + RUST_ENV + " cargo build --release --target x86_64-pc-windows-gnu 2>&1 | tail -6; "
             "ls -la target/x86_64-pc-windows-gnu/release/rsapp.exe 2>/dev/null | awk '{print \"size=\"$5}'", 500)

    print("\n[5] 产物校验（哈希 + 类型）")
    run(cli, "cd /tmp/xb && for f in a-pure.exe b-cgo.exe m-windows-amd64; do "
             "[ -f $f ] && printf '%-18s %s  %s\\n' $f $(sha256sum $f | cut -c1-16) $(file -b $f | cut -c1-45); done", 60)

    # ---------- 取回 Windows ----------
    print("\n[6] 传输到 Windows 并验证")
    os.makedirs(LOCAL_OUT, exist_ok=True)
    sftp = cli.open_sftp()
    local_hashes = {}
    for remote, localname in [
        ("/tmp/xb/a-pure.exe", "a-pure.exe"),
        ("/tmp/xb/b-cgo.exe", "b-cgo.exe"),
        ("/tmp/xb/m-windows-amd64", "m-windows-amd64.exe"),
    ]:
        try:
            dst = os.path.join(LOCAL_OUT, localname)
            sftp.get(remote, dst)
            h = hashlib.sha256(open(dst, "rb").read()).hexdigest()
            local_hashes[localname] = h
            print(f"    {localname}: {os.path.getsize(dst):,} 字节  sha256={h[:16]}")
        except OSError as e:
            print(f"    {localname}: 取回失败 {e}")
    # Rust 产物
    try:
        dst = os.path.join(LOCAL_OUT, "rsapp.exe")
        sftp.get("/tmp/xb/rsapp/target/x86_64-pc-windows-gnu/release/rsapp.exe", dst)
        local_hashes["rsapp.exe"] = hashlib.sha256(open(dst, "rb").read()).hexdigest()
        print(f"    rsapp.exe: {os.path.getsize(dst):,} 字节  sha256={local_hashes['rsapp.exe'][:16]}")
    except OSError as e:
        print(f"    rsapp.exe: 未取回（{e}）")
    sftp.close()

    # 远端哈希对比
    _in, out, _e = cli.exec_command(
        "cd /tmp/xb && sha256sum a-pure.exe b-cgo.exe m-windows-amd64 "
        "rsapp/target/x86_64-pc-windows-gnu/release/rsapp.exe 2>/dev/null", timeout=30)
    remote = {}
    for line in out.read().decode().splitlines():
        parts = line.split()
        if len(parts) == 2 and not parts[1].startswith("sha256sum"):
            remote[os.path.basename(parts[1])] = parts[0]
    print("\n    === 传输完整性（远端 vs 本地 sha256）===")
    for name, lh in local_hashes.items():
        rh = remote.get(name, "")
        mark = "一致 ✓" if rh and rh == lh else "不一致 ✗"
        print(f"    {name:20s} {mark}")

    cli.close()

    # ---------- Windows 侧执行验证 ----------
    print("\n[7] Windows 本机执行交叉编译产物")
    import subprocess
    for name in ("a-pure.exe", "b-cgo.exe", "m-windows-amd64.exe", "rsapp.exe"):
        path = os.path.join(LOCAL_OUT, name)
        if not os.path.exists(path):
            continue
        try:
            r = subprocess.run([path], capture_output=True, timeout=20)
            out_txt = (r.stdout or b"").decode("utf-8", "replace").strip()
            err_txt = (r.stderr or b"").decode("utf-8", "replace").strip()[:200]
            status = "✓" if r.returncode == 0 else f"✗ rc={r.returncode}"
            print(f"    {name:22s} {status}  输出: {out_txt or err_txt}")
        except Exception as e:  # noqa: BLE001
            print(f"    {name:22s} ✗ {type(e).__name__}: {e}")

    print("\n" + "=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
