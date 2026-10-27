#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Windows 交付包验收：单进程内完成 启动 → 全功能测试 → 退出。

之所以写成一个脚本：后台进程会随工具会话结束被回收，
把启动与测试放进同一次调用内才能拿到真实结果。
"""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import sys
import time
import urllib.error
import urllib.request

# 验收目录基于系统临时目录推导，避免硬编码绝对路径在换机后失效
BASE_DIR = os.path.join(tempfile.gettempdir(), "verify_zip", "密码管理器-桌面版")
DATA_DIR = os.path.join(BASE_DIR, "data")
EXE = os.path.join(BASE_DIR, "vaultd.exe")
PORT = 18310
BASE = f"http://127.0.0.1:{PORT}"

# 禁用代理：本机代理端口可能已死，会拖慢/阻断回环请求
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Client:
    def __init__(self):
        self.cookie = ""
        self.csrf = ""

    def _req(self, method, path, body=None):
        url = BASE + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with OPENER.open(req, timeout=30) as r:
                raw = r.read()
                for h, v in r.getheaders():
                    if h.lower() == "set-cookie":
                        self.cookie = v.split(";")[0]
                # 首页/静态资源返回 HTML 或 JS，不是 JSON
                ctype = r.headers.get("Content-Type", "")
                if "json" in ctype and raw:
                    return r.status, json.loads(raw)
                return r.status, {"_raw_len": len(raw), "_ctype": ctype}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, (json.loads(raw) if raw else {})
            except json.JSONDecodeError:
                return e.code, {"_raw": raw[:200].decode("utf-8", "replace")}

    def get(self, p):
        return self._req("GET", p)

    def post(self, p, b=None):
        return self._req("POST", p, b)

    def put(self, p, b=None):
        return self._req("PUT", p, b)

    def delete(self, p):
        return self._req("DELETE", p)


def check(label, cond, detail=""):
    mark = "✓" if cond else "✗"
    print(f"  {mark} {label}" + (f"  [{detail}]" if detail else ""))
    return cond


def main() -> int:
    if not os.path.exists(EXE):
        print(f"缺少 {EXE}")
        return 1

    # 清空数据，模拟全新解压
    if os.path.isdir(DATA_DIR):
        for name in os.listdir(DATA_DIR):
            p = os.path.join(DATA_DIR, name)
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)

    print("=== 0. 启动 Windows 可执行文件（全新数据目录）===")
    proc = subprocess.Popen(
        [EXE, "-open=false", "-addr", f"127.0.0.1:{PORT}"],
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(f"  PID = {proc.pid}")

    ready = False
    for _ in range(40):
        try:
            st, _d = Client().get("/api/status")
            if st == 200:
                ready = True
                break
        except Exception:  # noqa: BLE001
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    if not ready:
        print("  ✗ 服务未能启动")
        out = b""
        try:
            out, _ = proc.communicate(timeout=3)
        except Exception:  # noqa: BLE001
            proc.kill()
        print(out.decode("utf-8", "replace")[:800])
        return 1
    print("  ✓ 服务已就绪")

    c = Client()
    ok_all = True

    print("\n=== 1. 页面与静态资源 ===")
    for path, label in [("/", "首页"), ("/static/app.js", "app.js"), ("/static/app.css", "app.css")]:
        st, _ = c.get(path)
        ok_all &= check(f"GET {label}", st == 200, f"HTTP {st}")

    print("\n=== 2. 初始状态 ===")
    st, d = c.get("/api/status")
    ok_all &= check("未初始化检测", st == 200 and d.get("initialized") is False)
    ok_all &= check("Argon2id 可用", d.get("argon2_ready") is True)

    print("\n=== 3. 创建主账户 ===")
    st, d = c.post("/api/register", {
        "username": "winuser",
        "password": "WinLogin!2026",
        "master_password": "WinMaster!2026",
    })
    ok_all &= check("注册成功", st == 200 and d.get("ok") is True, str(d)[:80])
    ok_all &= check("下发 CSRF token", bool(d.get("csrf")))
    c.csrf = d.get("csrf", "")
    ok_all &= check("注册后即解锁", d.get("unlocked") is True)

    print("\n=== 4. 重复初始化应被拒绝 ===")
    # 注意：用户名需满足长度校验，否则会先命中「长度」错误，测不到「已初始化」分支
    st, d = c.post("/api/register", {
        "username": "another", "password": "Login!Pass2026", "master_password": "Master!Pass2026",
    })
    ok_all &= check("已初始化时拒绝重复注册", st == 400, str(d)[:60])

    print("\n=== 5. 分类 ===")
    st, d = c.post("/api/categories", {"name": "工作", "parent_id": 0, "icon": "briefcase"})
    ok_all &= check("创建分类", st == 200 and d.get("ok") is True)
    st, d = c.get("/api/categories")
    ok_all &= check("分类列表", st == 200 and len(d.get("categories") or []) == 1)

    print("\n=== 6. 密码条目 ===")
    st, d = c.post("/api/entries", {
        "title": "企业邮箱", "url": "mail.company.com", "username": "zhang@corp.com",
        "password": "Mail!Pass2026z", "notes": "双因素已开", "category_id": 1,
    })
    ok_all &= check("新增条目", st == 200 and d.get("ok") is True)

    st, d = c.get("/api/entries")
    entries = d.get("entries") or []
    ok_all &= check("列表返回 1 条", len(entries) == 1)
    # 关键：列表不得泄露密文或明文
    raw = json.dumps(entries, ensure_ascii=False)
    ok_all &= check("列表不含明文", "Mail!Pass2026z" not in raw)
    ok_all &= check("列表不含密文段", "cipher" not in raw)
    ok_all &= check("密码列显示掩码", entries[0].get("password_hint") == "••••••••")

    print("\n=== 7. 解密（主密钥由服务端持有）===")
    st, d = c.post("/api/entries/1/reveal")
    ok_all &= check("解密正确", st == 200 and d.get("password") == "Mail!Pass2026z", str(d)[:80])

    print("\n=== 8. CSRF 防护 ===")
    saved = c.csrf
    c.csrf = ""
    st, d = c.post("/api/entries", {"title": "x", "password": "y", "category_id": 0})
    ok_all &= check("无 token 被拒", st == 403, f"HTTP {st}")
    c.csrf = saved

    print("\n=== 9. 主密钥轮换（全量重加密）===")
    st, d = c.post("/api/change-master", {
        "old_password": "WinMaster!2026", "new_password": "WinMaster2!2026",
    })
    ok_all &= check("轮换成功", st == 200 and d.get("ok") is True, str(d)[:90])
    ok_all &= check("重加密 1 条", d.get("reencrypted") == 1)
    st, d = c.post("/api/entries/1/reveal")
    ok_all &= check("轮换后仍可解密", st == 200 and d.get("password") == "Mail!Pass2026z")

    print("\n=== 10. 锁定与解锁 ===")
    c.post("/api/lock")
    st, d = c.post("/api/entries/1/reveal")
    ok_all &= check("锁定后拒绝解密", st == 423, f"HTTP {st}")
    st, d = c.post("/api/unlock", {"password": "WinMaster2!2026"})
    ok_all &= check("重新解锁", st == 200 and d.get("unlocked") is True)
    st, d = c.post("/api/entries/1/reveal")
    ok_all &= check("解锁后可解密", st == 200)

    print("\n=== 11. 回收站 ===")
    st, _ = c.delete("/api/entries/1")
    ok_all &= check("移入回收站", st == 200)
    st, d = c.get("/api/entries?trash=1")
    ok_all &= check("回收站可见", len(d.get("entries") or []) == 1)
    st, _ = c.post("/api/entries/1/restore")
    ok_all &= check("恢复", st == 200)

    print("\n=== 12. 统计与备份 ===")
    st, d = c.get("/api/stats")
    ok_all &= check("统计", st == 200 and d.get("stats", {}).get("total_passwords") == 1)
    st, d = c.post("/api/backups")
    ok_all &= check("手动备份", st == 200 and d.get("ok") is True, d.get("filename", ""))
    backups = [f for f in os.listdir(os.path.join(DATA_DIR, "backups"))
               if f.endswith(".db")] if os.path.isdir(os.path.join(DATA_DIR, "backups")) else []
    ok_all &= check("备份文件落盘", len(backups) >= 1, f"{len(backups)} 个")

    print("\n=== 13. 数据库落盘与格式确认 ===")
    dbp = os.path.join(DATA_DIR, "passwords.db")
    ok_all &= check("数据库已创建", os.path.exists(dbp))
    if os.path.exists(dbp):
        con = sqlite3.connect(dbp)
        kdf = con.execute("select kdf_type, kdf_params from users").fetchone()
        ok_all &= check("KDF 为 argon2id", kdf[0] == "argon2id", f"{kdf[0]} {kdf[1]}")
        cipher = con.execute("select cipher from passwords").fetchone()[0]
        import base64
        ver = base64.b64decode(cipher)[0]
        ok_all &= check("密文为 v3 格式（首字节 0x03）", ver == 3, f"0x{ver:02x}")
        ok_all &= check("库中无明文密码", "Mail!Pass2026z" not in json.dumps(
            con.execute("select * from passwords").fetchall(), ensure_ascii=False))
        con.close()

    print("\n=== 14. 退出程序接口 ===")
    st, d = c.post("/api/shutdown")
    ok_all &= check("shutdown 返回成功", st == 200)
    exited = False
    for _ in range(20):
        if proc.poll() is not None:
            exited = True
            break
        time.sleep(0.25)
    ok_all &= check("进程已优雅退出", exited)
    if not exited:
        proc.kill()

    try:
        out, _ = proc.communicate(timeout=5)
    except Exception:  # noqa: BLE001
        out = b""
    print("\n--- 程序输出 ---")
    print(out.decode("utf-8", "replace").strip())

    print("\n" + "=" * 46)
    print("  总体结果：" + ("全部通过 ✓" if ok_all else "存在失败项 ✗"))
    print("=" * 46)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
