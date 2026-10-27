#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""交付包最终验收：解压 → 用 bat 启动 → 全功能 → 退出。

模拟真实用户路径，验证压缩包本身可用（而不只是源码编译出的 exe）。
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

ZIP = r"E:\WorkBuddy\2026-10-21-10-27-34\密码管理器-原生窗口版-Windows.zip"
DEST = os.path.join(os.environ["TEMP"], "verify_native")
PKG_DIR = "密码管理器-原生窗口版"
results = []


def chk(label, cond, detail=""):
    results.append((label, bool(cond), detail))
    print(("  ✓ " if cond else "  ✗ ") + label + (f"  [{detail}]" if detail else ""))
    return cond


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = ""
        self.csrf = ""
        self.op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, path, body=None, csrf=None):
        h = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        token = self.csrf if csrf is None else csrf
        if token:
            h["X-CSRF-Token"] = token
        if self.cookie:
            h["Cookie"] = self.cookie
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=data, headers=h, method=method)
        try:
            with self.op.open(req, timeout=30) as r:
                for k, v in r.getheaders():
                    if k.lower() == "set-cookie":
                        self.cookie = v.split(";")[0]
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return e.code, {"raw": raw[:160].decode("utf-8", "replace")}


def read_port(logpath, tries=50):
    for _ in range(tries):
        if os.path.exists(logpath):
            for line in open(logpath, encoding="utf-8", errors="replace").read().splitlines():
                if "服务端口:" in line:
                    try:
                        return int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
        time.sleep(0.3)
    return None


def main() -> int:
    print("=" * 54)
    print("交付包验收：解压 → bat 启动 → 全功能")
    print("=" * 54)

    # 1. 解压
    shutil.rmtree(DEST, ignore_errors=True)
    os.makedirs(DEST)
    with zipfile.ZipFile(ZIP) as zf:
        zf.extractall(DEST)
    root = os.path.join(DEST, PKG_DIR)
    print("\n[1] 解压结构")
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        print(f"    {name}" + ("/" if os.path.isdir(p) else f"  ({os.path.getsize(p):,} 字节)"))
    chk("vaultgui.exe 存在", os.path.exists(os.path.join(root, "vaultgui.exe")))
    chk("启动脚本存在", os.path.exists(os.path.join(root, "启动密码管理器.bat")))
    chk("README 存在", os.path.exists(os.path.join(root, "README.md")))

    # 2. 用 bat 启动（模拟双击）
    print("\n[2] 通过 bat 启动")
    bat = os.path.join(root, "启动密码管理器.bat")
    proc = subprocess.Popen(["cmd", "/c", bat], cwd=root,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = os.path.join(root, "data", "run.log")
    port = read_port(log)
    chk("bat 拉起了服务", port is not None, f"端口={port}")
    if not port:
        print("    日志：")
        if os.path.exists(log):
            print(open(log, encoding="utf-8", errors="replace").read()[:600])
        proc.terminate()
        return 1

    # 3. 窗口
    print("\n[3] 原生窗口")
    ps = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-Process msedge -ErrorAction SilentlyContinue | "
         "Where-Object { $_.MainWindowTitle -eq '密码管理器' }).Count"],
        capture_output=True, timeout=40).stdout.decode().strip()
    chk("存在「密码管理器」窗口", ps.isdigit() and int(ps) >= 1, f"count={ps}")

    # 4. 功能
    print("\n[4] 功能验收")
    c = Client(port)
    st, d = c.call("GET", "/api/status")
    chk("服务可用", st == 200)
    chk("Argon2id 就绪", d.get("argon2_ready") is True)

    st, d = c.call("POST", "/api/register",
                   {"username": "reluser", "password": "Rel!Pass2026",
                    "master_password": "RelM!Pass2026"})
    chk("注册", st == 200 and d.get("ok") is True)
    c.csrf = d.get("csrf", "")

    st, d = c.call("POST", "/api/entries",
                   {"title": "银行", "url": "bank.com", "username": "me",
                    "password": "Bank!Secret9", "notes": "", "category_id": 0})
    chk("新增密码", st == 200 and d.get("ok") is True)
    st, d = c.call("POST", "/api/entries/1/reveal")
    chk("解密", d.get("password") == "Bank!Secret9", str(d)[:50])

    st, d = c.call("POST", "/api/entries",
                   {"title": "x", "password": "y", "category_id": 0}, csrf="")
    chk("CSRF 拦截", st == 403, f"HTTP {st}")

    st, d = c.call("POST", "/api/backups")
    chk("备份", st == 200 and d.get("ok") is True, d.get("filename", ""))

    st, d = c.call("POST", "/api/generator",
                   {"length": 24, "upper": True, "lower": True,
                    "digits": True, "symbols": True, "avoid_amb": True})
    chk("密码生成器", len(d.get("password", "")) == 24)

    print("\n[5] 数据落在包内 data/")
    db = os.path.join(root, "data", "passwords.db")
    chk("数据库在 data/ 下", os.path.exists(db))
    chk("run.log 可读", os.path.exists(log))
    if os.path.exists(db):
        import sqlite3
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        row = con.execute("select kdf_type from users").fetchone()
        chk("KDF=argon2id", row and row[0] == "argon2id", str(row))
        con.close()

    print("\n[6] 退出")
    st, d = c.call("POST", "/api/shutdown")
    chk("shutdown 200", st == 200)
    time.sleep(3)
    alive = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-Process vaultgui -ErrorAction SilentlyContinue).Count"],
        capture_output=True, timeout=30).stdout.decode().strip()
    chk("主进程已退出", alive == "0" or alive == "", f"count={alive}")
    proc.terminate()

    ok = sum(1 for _, v, _ in results if v)
    bad = len(results) - ok
    print("\n" + "=" * 54)
    print(f"  通过 {ok} 项 / 失败 {bad} 项")
    print("=" * 54)
    if bad:
        for label, v, detail in results:
            if not v:
                print(f"  失败: {label}  [{detail}]")

    subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
