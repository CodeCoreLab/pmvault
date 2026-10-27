#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建 Windows 交付压缩包。

产物结构（解压即用）：
    密码管理器-桌面版/
      启动密码管理器.bat
      vaultd.exe
      data/            (空目录，首次运行自动建库)
      README.md
      使用说明.txt
"""
import io
import os
import socket
import struct
import subprocess
import sys
import tarfile
import zipfile

try:
    import paramiko
except ImportError:  # 本地编译路径不需要 paramiko
    paramiko = None

# 路径一律基于本脚本位置解析，不写死任何机器的绝对路径。
# 覆盖方式（可选）：设置环境变量 PMVAULT_OUT / PMVAULT_GO / PMVAULT_GOROOT / PMVAULT_GOPATH
_HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(_HERE)                       # phase-a/ 目录
OUT = os.environ.get("PMVAULT_OUT") or os.path.join(
    os.path.dirname(os.path.dirname(_HERE)), "dist")

# Go 工具链：优先用 PATH 上的 go，其次用环境变量指定的便携版
GO = os.environ.get("PMVAULT_GO") or "go"
GOROOT = os.environ.get("PMVAULT_GOROOT") or ""
GOPATH = os.environ.get("PMVAULT_GOPATH") or ""


def build_local(out_exe):
    """本地交叉编译 Windows 产物。

    比跳板机方案少一次 86KB 源码上传 + 一次 10MB 产物下载，
    也不受网络与远端环境波动影响。实测增量构建约 10s。
    """
    env = dict(os.environ)
    env.update({
        "GOPROXY": "off",
        "CGO_ENABLED": "0", "GOOS": "windows", "GOARCH": "amd64",
    })
    if GOROOT:
        env["GOROOT"] = GOROOT
    if GOPATH:
        env["GOPATH"] = GOPATH
    cmd = [GO, "build", "-trimpath",
           "-ldflags=-s -w -H windowsgui -X main.buildInfo=desktop-1.0.0",
           "-o", out_exe, "./cmd/vaultd"]
    print("[本地编译]", " ".join(cmd[:3]), "...")
    r = subprocess.run(cmd, cwd=SRC, env=env, capture_output=True)
    if r.returncode != 0:
        print("  编译失败:")
        print("  " + r.stderr.decode("utf-8", "replace")[:800])
        raise SystemExit(1)
    print("  编译通过")


ENV = ("export PATH=/opt/go/bin:$PATH GOPATH=/opt/gopath GOCACHE=/opt/gocache "
       "GOPROXY=https://goproxy.cn,direct GOFLAGS=-mod=mod;")

# bat 编码与换行铁律（实测踩坑）：
#   1. 必须 CRLF，否则 cmd 报 "was unexpected at this time"
#   2. 必须 GBK/CP936 编码，且去掉 chcp 65001：
#      cmd 在执行脚本前就已按当前代码页解析脚本文件，UTF-8 中文会被按 GBK
#      拆成非法字节序列，导致某行末字节被当成命令（实测报 "'的' is not
#      recognized"）。中文 Windows 默认代码页即 936，用 GBK 保存最稳。
#   3. 脚本特意在开头 chcp 65001，让 Go 程序的 UTF-8 中文日志正常显示；
#      但脚本自身的提示文字因此不能再含中文（GBK 字节会被按 UTF-8 解码成乱码），
#      故 bat 内的提示一律用 ASCII 英文，中文说明放在 使用说明.txt / README.md 里。
BAT = """@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Password Manager

echo.
echo   ==========================================
echo     Password Manager  starting...
echo   ==========================================
echo.
echo   Your browser will open automatically.
echo   Do NOT close this window while using it.
echo.
echo   To quit: click  Quit  in the top-right corner
echo   of the web page, or just close this window.
echo.

if not exist "%~dp0vaultd.exe" (
    echo   [ERROR] vaultd.exe not found.
    echo   Please extract the whole archive, not a single file.
    echo.
    pause
    exit /b 1
)

REM Use the full path from %~dp0, NOT the bare name.
REM When NoDefaultCurrentDirectoryInExePath=1 is set (hardened / enterprise
REM environments), cmd.exe stops searching the current directory for
REM executables: the bare name fails with 9009 while `if exist` still
REM succeeds, so the guard passes but the launch does not.
"%~dp0vaultd.exe"
if errorlevel 1 (
    echo.
    echo   Exited with error code %errorlevel%
    pause
)
"""


def run(cli, cmd, timeout=300, label=""):
    _in, out, err = cli.exec_command(cmd, timeout=timeout)
    try:
        body = out.read().decode("utf-8", "replace")
    except socket.timeout:
        body = "[timeout]"
    if label:
        print(f"--- {label} ---")
    if body.strip():
        print(body.rstrip()[:1200])
    return body


def pack_src() -> bytes:
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
    # 默认本地编译：本机已有 Go 便携工具链，无需连跳板机。
    # 跳板机方案保留在 build_on_jump()，异地/无本地工具链时可切换。
    local_dir = os.path.join(OUT, "dist-windows")
    os.makedirs(local_dir, exist_ok=True)
    local_exe = os.path.join(local_dir, "vaultd.exe")

    build_local(local_exe)

    size = os.path.getsize(local_exe)
    print(f"已构建 vaultd.exe: {size:,} 字节")

    # 组装压缩包
    pkg_root = "密码管理器-桌面版"
    zip_path = os.path.join(OUT, "密码管理器-桌面版-Windows.zip")

    readme = open(os.path.join(SRC, "README-桌面版.md"), encoding="utf-8").read()
    quick = (
        "密码管理器 - 桌面版\n"
        "========================================\n\n"
        "【启动】双击 vaultd.exe，浏览器会自动打开界面。\n"
        "        不会弹出命令行黑窗口，也没有启动脚本。\n\n"
        "【退出】点界面右上角「退出程序」，本地服务会一并停止。\n\n"
        "【数据】全部在 data\\ 目录里：\n"
        "        data\\passwords.db   主数据库（密码已加密）\n"
        "        data\\backups\\      自动备份（保留最近 30 份）\n\n"
        "        备份 = 整个文件夹复制走。换电脑 = 整个文件夹拷过去。\n\n"
        "【重要】两种密码不一样：\n"
        "        登录密码   —— 进系统用\n"
        "        主密钥密码 —— 加密数据用，丢失后数据永久无法恢复\n"
        "        建议二者不同，并牢记主密钥密码。\n\n"
        "【要求】Windows 10/11 64 位 + 任意现代浏览器。\n"
        "        无需安装 .NET / VC++ 运行库 / PHP，无需联网。\n\n"
        "【卸载】删除整个文件夹即可，不写注册表、不装服务。\n\n"
        "详细说明见 README.md\n"
    )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(local_exe, f"{pkg_root}/vaultd.exe")
        # 不再提供 .bat 启动器：vaultd.exe 已用 -H windowsgui 编译（PE Subsystem=2），
        # 双击直接启动服务并打开浏览器，不需要命令行窗口中转。
        zf.writestr(f"{pkg_root}/README.md", readme.encode("utf-8"))
        zf.writestr(f"{pkg_root}/使用说明.txt", quick.replace("\n", "\r\n").encode("gbk"))
        # 目录占位：确保解压后 data/ 存在（程序也会自建，双保险）
        zf.writestr(f"{pkg_root}/data/.keep", b"")

    zsize = os.path.getsize(zip_path)
    print(f"\n交付包: {zip_path}")
    print(f"  压缩后 {zsize:,} 字节（{zsize/1024/1024:.2f} MB）")
    print(f"  解压后约 {size/1024/1024:.1f} MB + 数据")

    with zipfile.ZipFile(zip_path) as zf:
        print("\n包内文件：")
        for info in zf.infolist():
            print(f"  {info.file_size:>9,}  {info.filename}")
        names = zf.namelist()

    # ---- 断言：形态正确 ----
    print("\n形态校验:")
    pe = check_pe(local_exe)
    print(f"  PE Subsystem = {pe['subsystem']}"
          f" {'(WINDOWS_GUI 无控制台，双击即用 ✓)' if pe['subsystem'] == 2 else '(仍有控制台 ✗)'}")
    print(f"  资源目录     = RVA 0x{pe['res_rva']:x} / {pe['res_size']} 字节")
    print(f"  图标数据     = {pe['icons_embedded']}/{pe['icons_total']} 张已嵌入")
    bats = [n for n in names if n.lower().endswith(".bat")]
    print(f"  启动脚本数量 = {len(bats)}"
          f" {'（已移除，无需 bat ✓）' if not bats else '（残留 ✗）'}")

    ok = (pe["subsystem"] == 2 and pe["res_rva"] != 0
          and pe["icons_embedded"] == pe["icons_total"] and not bats)
    print(f"\n结果: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 3


def check_pe(exe_path):
    """校验 PE 子系统与图标资源，避免「编译成功但形态错了」被静默发出去。"""
    d = open(exe_path, "rb").read()
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    optsz = struct.unpack_from("<H", d, lf + 20)[0]
    opt = lf + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    subsys = struct.unpack_from("<H", d, opt + 68)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    res_rva, res_size = struct.unpack_from("<II", d, dd + 8 * 2)

    ico_path = os.path.join(SRC, "cmd", "vaultd", "app.ico")
    embedded = total = 0
    if os.path.exists(ico_path):
        ico = open(ico_path, "rb").read()
        _, _, total = struct.unpack_from("<HHH", ico, 0)
        for i in range(total):
            w, h, _c, _r, _p, _b, sz, off = struct.unpack_from(
                "<BBBBHHII", ico, 6 + 16 * i)
            if ico[off:off + sz] in d:
                embedded += 1
    return {"subsystem": subsys, "res_rva": res_rva, "res_size": res_size,
            "icons_total": total, "icons_embedded": embedded}


if __name__ == "__main__":
    sys.exit(main())
