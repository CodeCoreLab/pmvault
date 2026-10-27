#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""模拟用户双击 bat：验证交付包里的启动脚本能拉起服务。

不调用 PowerShell（会被安全策略拦截），改用 netstat 解析监听端口。
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

BASE_DIR = r"C:\Users\Administrator\AppData\Local\Temp\verify_zip\密码管理器-桌面版"
DATA = os.path.join(BASE_DIR, "data")
BAT = os.path.join(BASE_DIR, "启动密码管理器.bat")
OP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def listening_port_of_vaultd():
    """用 netstat 找 vaultd.exe 的监听端口（避免调用 PowerShell）。"""
    try:
        out = subprocess.check_output(["netstat", "-ano", "-p", "TCP"],
                                      timeout=15, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        return None
    # 先拿 vaultd 的 PID
    pids = set()
    try:
        ps = subprocess.check_output(["tasklist", "/FI", "IMAGENAME eq vaultd.exe", "/FO", "CSV", "/NH"],
                                     timeout=15, stderr=subprocess.DEVNULL)
        for line in ps.decode("gb18030", "replace").splitlines():
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) >= 2 and parts[1].isdigit():
                pids.add(parts[1])
    except Exception:  # noqa: BLE001
        pass

    for line in out.decode("gb18030", "replace").splitlines():
        if "LISTENING" not in line:
            continue
        cols = line.split()
        if len(cols) < 5:
            continue
        if cols[-1] in pids:
            addr = cols[1]
            if ":" in addr:
                try:
                    return int(addr.rsplit(":", 1)[1])
                except ValueError:
                    continue
    return None


def main() -> int:
    for n in os.listdir(DATA):
        p = os.path.join(DATA, n)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)

    print(f"执行: {BAT}")
    proc = subprocess.Popen(["cmd", "/c", BAT], cwd=BASE_DIR,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    port, ok = None, False
    for _ in range(25):
        port = listening_port_of_vaultd()
        if port:
            try:
                with OP.open(f"http://127.0.0.1:{port}/api/status", timeout=5) as r:
                    if r.status == 200 and json.loads(r.read()).get("ok"):
                        ok = True
                        break
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.8)

    print(f"bat 拉起服务: {'✓ 成功' if ok else '✗ 失败'}   端口: {port}")

    if ok:
        with OP.open(f"http://127.0.0.1:{port}/", timeout=5) as r:
            body = r.read()
        print(f"首页 HTTP {r.status}，{len(body)} 字节，含「密码管理器」: {'密码管理器'.encode() in body}")
        # 走一遍注册，确认 bat 拉起的实例功能可用
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/register",
                data=json.dumps({"username": "batuser", "password": "Bat!Pass2026",
                                 "master_password": "BatMaster!2026"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with OP.open(req, timeout=45) as r:
                d = json.loads(r.read())
            print(f"bat 实例注册: {'✓' if d.get('ok') else '✗'}  unlocked={d.get('unlocked')}")
        except Exception as e:  # noqa: BLE001
            print("注册失败:", e)

    # 收尾：先请求退出，再兜底 kill
    try:
        subprocess.run(["taskkill", "/F", "/IM", "vaultd.exe"],
                       timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        pass
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=5)
    except Exception:  # noqa: BLE001
        out = b""

    print("\n--- bat 窗口输出（chcp 65001 后按 UTF-8 解码）---")
    for line in out.decode("utf-8", "replace").splitlines()[:12]:
        print("  " + line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
