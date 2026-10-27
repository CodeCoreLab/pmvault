#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""两个交付包的统一验收（均已是纯 exe，无 bat）。

判据聚焦「双击即用」这条真实用户路径：
  · 包里没有 .bat
  · exe 是 PE Subsystem=2（无控制台）
  · 图标嵌在 exe 里
  · 直接 CreateProcess 启动（等同双击），服务起来、功能可用

两个版本的日志格式不同，端口解析必须双通道：
  原生窗口版写 data/run.log 的「服务端口: N」
  浏览器版  写 data/run.log 的「已启动: http://127.0.0.1:N/」
  只认一种会把另一种判成启动失败（历史踩坑）。
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

# 以脚本自身位置推导仓库根，避免硬编码绝对路径在迁移后失效
_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
OP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
fails = []


def chk(label, cond, detail=""):
    print(("  [OK]  " if cond else "  [FAIL]") + " " + label
          + (f"   {detail}" if detail else ""))
    if not cond:
        fails.append(label)
    return cond


def kill():
    for n in ("vaultd.exe", "vaultgui.exe", "msedge.exe"):
        subprocess.run(["taskkill", "/F", "/IM", n],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def call(self, m, path, body=None, csrf=None):
        h, d = {}, None
        if body is not None:
            d = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if csrf:
            h["X-CSRF-Token"] = csrf
        if self.cookie:
            h["Cookie"] = self.cookie
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=d, headers=h, method=m)
        try:
            with OP.open(req, timeout=30) as r:
                for k, v in r.getheaders():
                    if k.lower() == "set-cookie":
                        self.cookie = v.split(";")[0]
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return e.code, {"raw": raw[:120].decode("utf-8", "replace")}


def pe_info(exe):
    d = open(exe, "rb").read()
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    optsz = struct.unpack_from("<H", d, lf + 20)[0]
    opt = lf + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    subsys = struct.unpack_from("<H", d, opt + 68)[0]
    # 数据目录每项 8 字节；PE32+ 起点 opt+112，PE32 起点 opt+96
    dd = opt + (112 if magic == 0x20B else 96)
    res_rva, res_size = struct.unpack_from("<II", d, dd + 8 * 2)
    return subsys, res_rva, res_size


def parse_port(log, tries=60):
    """双通道解析端口：既认「服务端口: N」也认「http://127.0.0.1:N/」。"""
    for _ in range(tries):
        if os.path.exists(log):
            try:
                txt = open(log, encoding="utf-8", errors="replace").read()
            except OSError:
                txt = ""
            for line in txt.splitlines():
                if "服务端口" in line:
                    tail = line.split(":")[-1].strip().rstrip("/")
                    if tail.isdigit():
                        return int(tail)
                if "127.0.0.1:" in line:
                    frag = line.split("127.0.0.1:")[-1]
                    num = ""
                    for c in frag:
                        if c.isdigit():
                            num += c
                        else:
                            break
                    if num:
                        return int(num)
        time.sleep(0.5)
    return None


def verify(zip_name, pkg, exe_name, tag):
    print("\n" + "=" * 58)
    print(f"  {tag}")
    print("=" * 58)
    kill()
    time.sleep(1)
    base = os.path.join(os.environ["TEMP"], f"final2_{tag}")
    if os.path.exists(base):
        shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    zipfile.ZipFile(os.path.join(ROOT, zip_name)).extractall(base)
    root = os.path.join(base, pkg)
    files = sorted(os.listdir(root))
    print("  解压内容:", files)

    chk(f"{exe_name} 存在", exe_name in files)
    chk("不含任何 .bat", not any(f.lower().endswith(".bat") for f in files))

    exe = os.path.join(root, exe_name)
    subsys, res_rva, res_size = pe_info(exe)
    chk("PE Subsystem=2（无控制台）", subsys == 2, f"subsystem={subsys}")
    chk("图标资源已嵌入", res_rva != 0 and res_size > 0,
        f"RVA=0x{res_rva:x} size={res_size}")

    print("\n  [启动] 直接双击 exe（不经任何脚本）")
    p = subprocess.Popen([exe], cwd=root, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=0x00000008)
    port = parse_port(os.path.join(root, "data", "run.log"))
    chk("服务启动成功", bool(port), f"port={port}")
    if not port:
        kill()
        return

    c = Client(port)
    st, d = c.call("GET", "/api/status")
    chk("API 可用", st == 200)
    chk("Argon2id 就绪", d.get("argon2_ready") is True)

    st, d = c.call("POST", "/api/register",
                   {"username": f"{tag}user", "password": "Fin!Pass2026",
                    "master_password": "FinM!Pass2026"})
    chk("注册", st == 200 and d.get("ok") is True, str(d)[:40])
    csrf = d.get("csrf")

    st, d = c.call("POST", "/api/entries",
                   {"title": "验收条目", "url": "a.com", "username": "u",
                    "password": "Chk!Secret9", "notes": "", "category_id": 0}, csrf)
    chk("新增密码", st == 200 and d.get("ok") is True)
    st, d = c.call("POST", "/api/entries/1/reveal", None, csrf)
    chk("解密正确", d.get("password") == "Chk!Secret9", str(d)[:36])
    st, d = c.call("POST", "/api/entries",
                   {"title": "x", "password": "y", "category_id": 0})
    chk("CSRF 拦截 403", st == 403, f"HTTP {st}")
    st, d = c.call("POST", "/api/backups", None, csrf)
    chk("备份", st == 200 and d.get("ok") is True)

    db = os.path.join(root, "data", "passwords.db")
    chk("数据在 exe 同级 data/", os.path.exists(db))
    if os.path.exists(db):
        import sqlite3
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        row = con.execute("select kdf_type from users").fetchone()
        chk("KDF=argon2id", bool(row) and row[0] == "argon2id", str(row))
        con.close()

    st, d = c.call("POST", "/api/shutdown", None, csrf)
    chk("shutdown 返回成功", st == 200)
    time.sleep(3)
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-Process {exe_name[:-4]} -ErrorAction SilentlyContinue).Count"],
        capture_output=True, timeout=30)
    cnt = r.stdout.decode("utf-8", "replace").strip() or "0"
    chk("进程已退出", cnt == "0", f"count={cnt}")
    kill()


def main():
    print("#" * 58)
    print("#  双包验收：纯 exe，双击即用，无启动脚本")
    print("#" * 58)
    verify("密码管理器-原生窗口版-Windows.zip", "密码管理器-原生窗口版",
           "vaultgui.exe", "native")
    verify("密码管理器-桌面版-Windows.zip", "密码管理器-桌面版",
           "vaultd.exe", "browser")

    print("\n" + "=" * 58)
    if fails:
        print(f"  失败 {len(fails)} 项:")
        for f in fails:
            print("    -", f)
    else:
        print("  两个包全部通过")
    print("=" * 58)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
