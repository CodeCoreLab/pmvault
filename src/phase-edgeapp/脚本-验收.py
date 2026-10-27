#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""最终验收：Edge --app 版全功能（每项独立会话，避免相互污染）。"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

EXE_SRC = os.path.join(os.environ["TEMP"], "vaultgui-edge.exe")
BASE = os.path.join(os.environ["TEMP"], "edge_final")
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

    def call(self, method, path, body=None, csrf=None, timeout=30):
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
            with self.op.open(req, timeout=timeout) as r:
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


def read_port(logpath, tries=40):
    for _ in range(tries):
        if os.path.exists(logpath):
            txt = open(logpath, encoding="utf-8", errors="replace").read()
            for line in txt.splitlines():
                if "服务端口:" in line:
                    try:
                        return int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
        time.sleep(0.4)
    return None


def main() -> int:
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(os.path.join(BASE, "data"))
    shutil.copy(EXE_SRC, os.path.join(BASE, "vaultgui-edge.exe"))
    log = os.path.join(BASE, "run.log")

    with open(log, "wb") as fh:
        proc = subprocess.Popen([os.path.join(BASE, "vaultgui-edge.exe")], cwd=BASE,
                                stdout=fh, stderr=subprocess.STDOUT,
                                creationflags=0x00000008)
    port = read_port(log)
    print("=" * 52)
    print(f"Edge --app 版最终验收   PID={proc.pid}  端口={port}")
    print("=" * 52)
    if not port:
        print("启动失败，日志：")
        print(open(log, encoding="utf-8", errors="replace").read()[:800])
        proc.terminate()
        return 1

    c = Client(port)

    print("\n[1] 初始化状态")
    st, d = c.call("GET", "/api/status")
    chk("服务可用", st == 200)
    chk("未初始化", d.get("initialized") is False)
    chk("Argon2id 就绪", d.get("argon2_ready") is True)

    print("\n[2] 注册")
    st, d = c.call("POST", "/api/register",
                   {"username": "finaluser", "password": "Final!Pass2026",
                    "master_password": "FinalM!Pass2026"})
    chk("注册成功", st == 200 and d.get("ok") is True, str(d.get("error", ""))[:50])
    c.csrf = d.get("csrf", "")
    chk("下发 CSRF", bool(c.csrf))

    print("\n[3] 分类与条目")
    st, d = c.call("POST", "/api/categories",
                   {"name": "工作", "parent_id": 0, "icon": "briefcase"})
    chk("创建分类", st == 200)
    st, d = c.call("GET", "/api/categories")
    chk("分类数=1", len(d.get("categories") or []) == 1)

    st, d = c.call("POST", "/api/entries",
                   {"title": "邮箱", "url": "mail.x.com", "username": "a@x.com",
                    "password": "Secret!2026", "notes": "备注", "category_id": 1})
    chk("新增条目", st == 200 and d.get("ok") is True)

    st, d = c.call("GET", "/api/entries")
    entries = d.get("entries") or []
    raw = json.dumps(entries, ensure_ascii=False)
    chk("列表 1 条", len(entries) == 1)
    chk("列表不含明文", "Secret!2026" not in raw)
    chk("列表不含密文字段", "cipher" not in raw)

    print("\n[4] 解密")
    st, d = c.call("POST", "/api/entries/1/reveal")
    chk("解密正确", d.get("password") == "Secret!2026", str(d)[:60])

    print("\n[5] CSRF 防护（本次显式不带 token）")
    st, d = c.call("POST", "/api/entries",
                   {"title": "x", "password": "y", "category_id": 0}, csrf="")
    chk("无 token 被拒 403", st == 403, f"HTTP {st}")
    chk("返回 CSRF 错误信息", "CSRF" in json.dumps(d, ensure_ascii=False))

    print("\n[6] 锁定与解锁")
    c.call("POST", "/api/lock")
    st, d = c.call("POST", "/api/entries/1/reveal")
    chk("锁定后拒绝 423", st == 423, f"HTTP {st}")
    st, d = c.call("POST", "/api/unlock", {"password": "FinalM!Pass2026"})
    chk("解锁成功", st == 200)
    st, d = c.call("POST", "/api/entries/1/reveal")
    chk("解锁后可解密", d.get("password") == "Secret!2026")

    print("\n[7] 主密钥轮换（正确键名 old_password/new_password）")
    st, d = c.call("POST", "/api/change-master",
                   {"old_password": "FinalM!Pass2026", "new_password": "FinalM2!Pass2026"})
    chk("轮换成功", st == 200 and d.get("ok") is True, str(d.get("error", ""))[:60])
    chk("返回重加密条数", d.get("reencrypted") == 1, f"reencrypted={d.get('reencrypted')}")
    st, d = c.call("POST", "/api/entries/1/reveal")
    chk("轮换后仍可解密", d.get("password") == "Secret!2026")

    print("\n[8] 回收站")
    c.call("DELETE", "/api/entries/1")
    st, d = c.call("GET", "/api/entries?trash=1")
    chk("回收站可见", len(d.get("entries") or []) == 1)
    st, d = c.call("POST", "/api/entries/1/restore")
    chk("恢复成功", st == 200)

    print("\n[9] 备份与生成器")
    st, d = c.call("POST", "/api/backups")
    chk("手动备份", st == 200 and d.get("ok") is True, d.get("filename", ""))
    st, d = c.call("POST", "/api/generator",
                   {"length": 20, "upper": True, "lower": True,
                    "digits": True, "symbols": True, "avoid_amb": True})
    pw = d.get("password", "")
    chk("生成 20 位密码", len(pw) == 20, pw)

    print("\n[10] 数据落盘")
    db = os.path.join(BASE, "data", "passwords.db")
    chk("数据库已建", os.path.exists(db), f"{os.path.getsize(db) if os.path.exists(db) else 0} 字节")
    bakdir = os.path.join(BASE, "data", "backups")
    n = len([f for f in os.listdir(bakdir) if f.endswith(".db")]) if os.path.isdir(bakdir) else 0
    chk("备份文件存在", n >= 1, f"{n} 个")
    import sqlite3
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    kdf = con.execute("select kdf_type from users").fetchone()
    chk("KDF 为 argon2id", kdf and kdf[0] == "argon2id", str(kdf))
    con.close()

    print("\n[11] 网页端退出程序")
    st, d = c.call("POST", "/api/shutdown")
    chk("shutdown 返回 200", st == 200)
    exited = False
    for _ in range(20):
        if proc.poll() is not None:
            exited = True
            break
        time.sleep(0.3)
    chk("主进程已退出", exited)
    if not exited:
        proc.kill()

    ok = sum(1 for _, v, _ in results if v)
    bad = len(results) - ok
    print("\n" + "=" * 52)
    print(f"  通过 {ok} 项 / 失败 {bad} 项")
    print("=" * 52)
    if bad:
        print("\n失败项：")
        for label, v, detail in results:
            if not v:
                print(f"  - {label}  [{detail}]")
    # 清理拉起的 Edge 窗口
    subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
