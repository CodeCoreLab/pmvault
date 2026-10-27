#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""UI 端到端验收：用真实浏览器点界面，而不是只打 API。

为什么必须做：前几轮验收全走 HTTP API，前端 JS 报错、选择器错位、
表单提交没接上这类问题一律发现不了 —— 而用户实际接触的就是这个页面。

覆盖路径（模拟真实用户）：
  1. 全新安装 → 注册（用户名 / 登录密码 / 主密钥密码）
  2. 进入主界面 → 新建分类 → 添加密码
  3. 点「显示」按钮解密
  4. 搜索过滤
  5. 锁定 → 解锁
  6. 退出程序

判据全部来自页面上的可见文本 / DOM 状态，不看 API 返回值。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

from playwright.sync_api import sync_playwright

# 以脚本自身位置推导仓库根，避免硬编码绝对路径在迁移后失效
_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
ZIP = os.path.join(ROOT, "releases", "密码管理器-桌面版-Windows.zip")
PKG = "密码管理器-桌面版"
WORK = os.path.join(os.environ["TEMP"], "ui_e2e")

USER = "uiuser"
LOGIN_PW = "UiLogin!2026x"
MASTER_PW = "UiMaster!2026x"
ENTRY_TITLE = "招行网银"
ENTRY_PW = "Bank!Secret99"

fails = []
shots = []
total = 0


def chk(label, cond, detail=""):
    global total
    total += 1
    mark = "[OK]  " if cond else "[FAIL]"
    print(f"  {mark} {label}" + (f"   {detail}" if detail else ""))
    if not cond:
        fails.append(label)
    return cond


def start_server():
    """解压后直接启动 exe（无 bat），返回 (进程, 包根目录, 端口)。"""
    if os.path.exists(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    zipfile.ZipFile(ZIP).extractall(WORK)
    base = os.path.join(WORK, PKG)
    # 包内已无启动脚本：exe 是 PE Subsystem=2，双击即启动
    p = subprocess.Popen([os.path.join(base, "vaultd.exe")], cwd=base,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x00000008)
    log = os.path.join(base, "data", "run.log")
    port = None
    for _ in range(60):
        if os.path.exists(log):
            try:
                txt = open(log, encoding="utf-8", errors="replace").read()
            except OSError:
                txt = ""
            for line in txt.splitlines():
                if "已启动" in line and "127.0.0.1:" in line:
                    frag = line.split("127.0.0.1:")[-1]
                    num = ""
                    for c in frag:
                        if c.isdigit():
                            num += c
                        else:
                            break
                    if num:
                        port = int(num)
            if port:
                break
        time.sleep(0.5)
    return p, base, port


def shot(page, name):
    path = os.path.join(WORK, f"{name}.png")
    page.screenshot(path=path)
    shots.append(path)
    return path


def find_browser():
    """找一个本机已存在的 chromium 内核（优先 headless shell，其次完整 chrome）。

    Playwright 库要求的版本号常比实际安装的新，直接指定路径可跳过匹配。
    """
    base = os.path.join(os.environ["LOCALAPPDATA"], "ms-playwright")
    if not os.path.isdir(base):
        return None
    found = []
    for d in sorted(os.listdir(base), reverse=True):
        if d.startswith("chromium_headless_shell-"):
            p = os.path.join(base, d, "chrome-headless-shell-win64",
                             "chrome-headless-shell.exe")
            if os.path.exists(p):
                found.append(p)
    for d in sorted(os.listdir(base), reverse=True):
        if d.startswith("chromium-"):
            p = os.path.join(base, d, "chrome-win", "chrome.exe")
            if os.path.exists(p):
                found.append(p)
    return found[0] if found else None


def main():
    print("=" * 58)
    print("  UI 端到端验收（真实浏览器点界面）")
    print("=" * 58)

    proc, base, port = start_server()
    chk("服务启动（来自 bat）", bool(port), f"port={port}")
    if not port:
        kill()
        return 1

    url = f"http://127.0.0.1:{port}/"
    console_errors = []

    with sync_playwright() as pw:
        # 本机 Playwright 库版本比已装内核新（要 1243，实际有 1224），
        # 直接指定可执行文件，跳过版本匹配检查。
        exe = find_browser()
        if exe:
            print(f"  浏览器内核: {exe}")
            browser = pw.chromium.launch(headless=True, executable_path=exe)
        else:
            browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 820},
                                  locale="zh-CN")
        page = ctx.new_page()
        # 捕获 JS 报错：前端逻辑坏了时 API 层面看不出来，这里能立刻暴露
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(f"pageerror: {e}"))

        print("\n[1] 打开页面")
        page.goto(url, wait_until="networkidle")
        chk("页面标题正确", "密码管理器" in page.title(), page.title())
        auth_visible = page.is_visible("#authView")
        chk("首屏显示登录/注册卡片", auth_visible)
        chk("主界面初始隐藏", not page.is_visible("#mainView"))
        shot(page, "01_首屏")

        print("\n[2] 全新安装 → 注册")
        hint = page.inner_text("#authTitle")
        print(f"    卡片标题: {hint!r}")
        # 产品文案是「创建主账户」，不是「注册」——断言应校验「是不是首次引导」
        chk("引导为首次创建账户", "创建主账户" in hint or "注册" in hint, hint)
        chk("显示主密钥输入框", page.is_visible("#masterField"))

        page.fill("#username", USER)
        page.fill("#password", LOGIN_PW)
        page.fill("#masterPassword", MASTER_PW)
        page.click("#authSubmit")
        page.wait_for_timeout(2500)
        chk("注册后进入主界面", page.is_visible("#mainView"))
        chk("登录卡片已隐藏", not page.is_visible("#authView"))
        shot(page, "02_主界面")

        print("\n[3] 新建分类")
        page.click("#btnAddCategory")
        page.wait_for_timeout(600)
        chk("分类对话框打开", page.is_visible("#catDialog"))
        page.fill("#catName", "金融")
        page.click("#catDialog button[type=submit]")
        page.wait_for_timeout(1500)
        cat_text = page.inner_text("#categoryList")
        chk("分类出现在侧栏", "金融" in cat_text, cat_text.replace("\n", " / ")[:60])
        shot(page, "03_分类")

        print("\n[4] 添加密码")
        page.click("#btnAddEntry")
        page.wait_for_timeout(600)
        chk("条目对话框打开", page.is_visible("#entryDialog"))
        page.fill("#eTitle", ENTRY_TITLE)
        page.fill("#eUrl", "cmbchina.com")
        page.fill("#eUsername", "me@corp.com")
        page.fill("#ePassword", ENTRY_PW)
        page.fill("#eNotes", "U 盾在家")
        # 分类选择：优先选刚建的「金融」
        try:
            page.select_option("#eCategory", label=re.compile("金融"))
        except Exception:  # noqa: BLE001
            print("    (分类下拉未选中「金融」，用默认值)")
        page.click("#entryDialog button[type=submit]")
        page.wait_for_timeout(1800)
        rows = page.inner_text("#entryRows")
        chk("条目出现在列表", ENTRY_TITLE in rows, rows.replace("\n", " / ")[:80])
        chk("列表不显示明文密码", ENTRY_PW not in rows, "已遮蔽" if ENTRY_PW not in rows else "泄露!")
        shot(page, "04_条目列表")

        print("\n[5] 点「查看」按钮解密")
        review = page.locator("#entryRows tr").first.get_by_text("查看", exact=True)
        chk("找到「查看」按钮", review.count() >= 1, f"count={review.count()}")
        review.first.click()
        page.wait_for_timeout(1800)
        pwd_cell = page.locator("#entryRows tr").first.locator("td.mono").nth(1)
        cell_text = pwd_cell.inner_text()
        rows_after = page.inner_text("#entryRows")
        chk("解密后密码格显示明文", ENTRY_PW in rows_after,
            f"密码格={cell_text!r}")
        # 「查看」是每次点击解密该条目的按需按钮，解锁后依然存在，属设计如此，
        # 不作「应消失」断言（早先这条断言是错的）。
        shot(page, "05_解密后")

        print("\n[6] 搜索过滤")
        page.fill("#search", "招行")
        page.wait_for_timeout(1200)
        hit = page.inner_text("#entryRows")
        chk("搜索命中", ENTRY_TITLE in hit)
        page.fill("#search", "不存在的关键词xyz")
        page.wait_for_timeout(1200)
        miss = page.inner_text("#entryRows")
        chk("无匹配时列表为空/提示", ENTRY_TITLE not in miss,
            miss.replace("\n", " / ")[:50])
        page.fill("#search", "")
        page.wait_for_timeout(1000)

        print("\n[7] 锁定 → 解锁")
        # 先解密一条，再锁定，验证明文不被残留在页面上
        page.locator("#entryRows tr").first.get_by_text("查看", exact=True).first.click()
        page.wait_for_timeout(1200)
        before_lock = page.inner_text("#entryRows")
        chk("锁定前已显示明文", ENTRY_PW in before_lock)

        page.click("#btnLock")
        page.wait_for_timeout(1500)
        chk("锁定后出现提示条", page.is_visible("#lockBanner"))
        after_lock = page.inner_text("#entryRows")
        chk("锁定后明文立刻消失（不等 15s 定时器）", ENTRY_PW not in after_lock,
            "已遮蔽" if ENTRY_PW not in after_lock else "明文仍残留!")

        page.click("#btnUnlock")
        page.wait_for_timeout(800)
        chk("解锁对话框打开", page.is_visible("#unlockDialog"))
        page.fill("#unlockPassword", MASTER_PW)
        page.click("#unlockDialog button[type=submit]")
        page.wait_for_timeout(2000)
        chk("解锁后提示条消失", not page.is_visible("#lockBanner"))
        shot(page, "06_解锁后")

        print("\n[8] JS 报错 / CSP 违规检查")
        real = [e for e in console_errors if "favicon" not in e.lower()]
        if real:
            print("    捕获到错误:")
            for e in real[:8]:
                print("      ", e[:170])
        chk("无 JS 控制台错误 / CSP 违规", len(real) == 0, f"{len(real)} 条")

        print("\n[9] 退出程序")
        # 「退出程序」会先弹 confirm，Playwright 默认自动取消 —— 必须显式接受，
        # 否则按钮逻辑根本不执行，会误判为「退出失败」。
        page.on("dialog", lambda d: d.accept())
        page.click("#btnShutdown")
        page.wait_for_timeout(3000)
        chk("页面显示已退出提示",
            "程序已退出" in page.inner_text("body"))
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process vaultd -ErrorAction SilentlyContinue).Count"],
            capture_output=True, timeout=30)
        cnt = r.stdout.decode("utf-8", "replace").strip() or "0"
        chk("点「退出程序」后服务进程消失", cnt == "0", f"count={cnt}")
        shot(page, "07_已退出")

        browser.close()

    kill()
    print("\n" + "=" * 58)
    print(f"  检查项共 {total} 项，失败 {len(fails)} 项")
    if fails:
        print(f"  失败 {len(fails)} 项:")
        for f in fails:
            print("    -", f)
    else:
        print("  全部通过")
    print(f"  截图 {len(shots)} 张，在 {WORK}")
    print("=" * 58)
    return 0 if not fails else 1


def kill():
    for n in ("vaultd.exe", "vaultgui.exe", "msedge.exe"):
        subprocess.run(["taskkill", "/F", "/IM", n],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    sys.exit(main())
