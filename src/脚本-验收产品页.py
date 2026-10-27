#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""产品页视觉验收：多视口截图 + 关键断言。

为什么要跑：CSS 写错不会报错，HTTP 200 不代表样式生效。
必须真实渲染后放大看，并测量 DOM 才能确认布局没崩。
"""
import os
import sys

from playwright.sync_api import sync_playwright

ROOT = r"E:\WorkBuddy\2026-10-21-10-27-34"
PAGE = "file:///" + os.path.join(ROOT, "密码管理器-产品介绍页.html").replace("\\", "/")
OUT = os.path.join(os.environ["TEMP"], "pp_shot")
os.makedirs(OUT, exist_ok=True)

fails = []


def chk(label, cond, detail=""):
    print(("  [OK]  " if cond else "  [FAIL]") + " " + label
          + (f"   {detail}" if detail else ""))
    if not cond:
        fails.append(label)
    return cond


def find_browser():
    base = os.path.join(os.environ["LOCALAPPDATA"], "ms-playwright")
    for d in sorted(os.listdir(base), reverse=True):
        if d.startswith("chromium_headless_shell-"):
            p = os.path.join(base, d, "chrome-headless-shell-win64",
                             "chrome-headless-shell.exe")
            if os.path.exists(p):
                return p
    return None


with sync_playwright() as pw:
    exe = find_browser()
    browser = pw.chromium.launch(headless=True, executable_path=exe)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                              locale="zh-CN", device_scale_factor=2)
    page = ctx.new_page()
    errs = []
    page.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errs.append(f"pageerror: {e}"))

    print("=" * 58)
    print("  产品页视觉验收")
    print("=" * 58)

    page.goto(PAGE, wait_until="networkidle")
    page.wait_for_timeout(1200)

    print("\n[1] 基础")
    chk("标题正确", "密码管理器" in page.title(), page.title())
    chk("无 JS 报错", len(errs) == 0, f"{len(errs)} 条")
    if errs:
        for e in errs[:5]:
            print("      ", e[:150])

    # 首屏
    page.screenshot(path=os.path.join(OUT, "01_hero.png"))
    print("\n[2] 首屏")
    h1 = page.inner_text("h1")
    print(f"    H1: {h1!r}")
    chk("H1 非空", len(h1.strip()) > 4)
    # 测量强调色是否生效（em 应显示品牌绿）
    em_color = page.evaluate(
        "getComputedStyle(document.querySelector('h1 em')).color")
    print(f"    H1 强调色: {em_color}")
    chk("强调色已应用（非纯黑）", "0, 0, 0" not in em_color)

    # 密文动画是否在动
    t1 = page.inner_text("#cipherLine")
    page.wait_for_timeout(500)
    t2 = page.inner_text("#cipherLine")
    chk("密文演示在动（文本变化）", t1 != t2, f"{t1[:16]!r} → {t2[:16]!r}")

    # 各区块
    print("\n[3] 区块完整性")
    for sel, name in [("#capabilities", "能力"), ("#security", "安全"),
                      ("#threat", "边界"), ("#editions", "版本"),
                      ("#download", "下载")]:
        n = page.locator(sel).count()
        chk(f"{name}区存在", n >= 1, sel)

    # 能力网格应为 3 列
    cols = page.evaluate("""() => {
      const g = document.querySelector('.cap-grid');
      return getComputedStyle(g).gridTemplateColumns.split(' ').length;
    }""")
    chk("能力网格为 3 列", cols == 3, f"{cols} 列")

    # 横向溢出检查（最常见布局崩坏）
    print("\n[4] 溢出与排版")
    overflow = page.evaluate("""() => {
      const d = document.documentElement;
      return { sw: d.scrollWidth, cw: d.clientWidth };
    }""")
    chk("无横向溢出", overflow["sw"] <= overflow["cw"] + 1,
        f"scrollW={overflow['sw']} clientW={overflow['cw']}")

    # 内容可见性：不能有任何 .reveal 停留在 opacity 0
    # （早先整页空白就是因为 IntersectionObserver 未触发而内容永久隐藏）
    hidden = page.evaluate("""() => {
      const bad = [];
      document.querySelectorAll('.reveal').forEach((el) => {
        if (parseFloat(getComputedStyle(el).opacity) < 0.05) {
          bad.push((el.innerText || '').slice(0, 18).replace(/\\s+/g, ' '));
        }
      });
      return bad;
    }""")
    chk("无永久隐藏的内容块", len(hidden) == 0,
        f"{len(hidden)} 块不可见" if hidden else "")
    if hidden:
        for h in hidden[:4]:
            print("      隐藏:", h)

    # 正文行宽不宜过宽
    measure = page.evaluate("""() => {
      const p = document.querySelector('.section-head p');
      const cs = getComputedStyle(p);
      const ch = parseFloat(cs.fontSize) * 0.52;
      return Math.round(p.getBoundingClientRect().width / ch);
    }""")
    chk("正文行宽合理（<75ch）", measure < 75, f"约 {measure} ch")

    # 滚动到中部截图
    page.evaluate("document.querySelector('#security').scrollIntoView()")
    page.wait_for_timeout(900)
    page.screenshot(path=os.path.join(OUT, "02_security.png"))

    page.evaluate("document.querySelector('#threat').scrollIntoView()")
    page.wait_for_timeout(900)
    page.screenshot(path=os.path.join(OUT, "03_threat.png"))

    page.evaluate("document.querySelector('#download').scrollIntoView()")
    page.wait_for_timeout(900)
    page.screenshot(path=os.path.join(OUT, "04_download.png"))

    # 下载链接指向
    print("\n[5] 下载链接")
    hrefs = page.eval_on_selector_all(".dl-btn", "els => els.map(e => e.getAttribute('href'))")
    for h in hrefs:
        exists = os.path.exists(os.path.join(ROOT, h))
        chk(f"目标存在: {h}", exists)

    # 移动端
    print("\n[6] 移动端 390px")
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(900)
    page.evaluate("window.scrollTo(0,0)")
    page.wait_for_timeout(400)
    page.screenshot(path=os.path.join(OUT, "05_mobile_hero.png"))
    ov = page.evaluate("""() => {
      const d = document.documentElement;
      return { sw: d.scrollWidth, cw: d.clientWidth };
    }""")
    chk("移动端无横向溢出", ov["sw"] <= ov["cw"] + 1,
        f"scrollW={ov['sw']} clientW={ov['cw']}")
    # 网格应降为单列
    mcols = page.evaluate("""() => {
      const g = document.querySelector('.cap-grid');
      return getComputedStyle(g).gridTemplateColumns.split(' ').length;
    }""")
    chk("移动端能力网格为 1 列", mcols == 1, f"{mcols} 列")

    page.evaluate("document.querySelector('#download').scrollIntoView()")
    page.wait_for_timeout(700)
    page.screenshot(path=os.path.join(OUT, "06_mobile_download.png"))

    browser.close()

print("\n" + "=" * 58)
if fails:
    print(f"  失败 {len(fails)} 项:")
    for f in fails:
        print("    -", f)
else:
    print("  全部通过")
print(f"  截图: {OUT}")
print("=" * 58)
sys.exit(0 if not fails else 1)
