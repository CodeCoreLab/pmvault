#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建原生窗口版 Windows 交付包（纯 exe，无 bat 启动器）。

为什么去掉 bat：
  vaultgui.exe 用 -H windowsgui 编译，PE Subsystem=2（WINDOWS_GUI），
  双击直接出窗口，本身就是一个完整的桌面应用。
  之前的「启动密码管理器.bat」只是历史遗留 —— 那是为了浏览器版
  （Subsystem=3，有控制台，双击会闪一个黑框）才需要的中间层。
  GUI 版再套一层 bat，等于把成品又包了层壳，还带出两个副作用：
    · 用户看到一个黑色命令行窗口，观感像脚本而非软件
    · bat 的裸文件名调用在 NoDefaultCurrentDirectoryInExePath=1 环境下失败

  去掉后仍具备全部必要能力（均已实测）：
    · 双击启动        —— Subsystem=2，无控制台
    · 单一实例        —— Global\\PasswordManagerGUI_SingleInstance_v1 命名互斥量
    · 启动失败可见    —— MessageBoxW 弹窗（非 mshta，无子进程）
    · 排障入口        —— data/run.log 文件日志
    · 图标            —— app.ico → rsrc_windows_amd64.syso 链入 exe

交付结构（解压即用）：
    密码管理器-原生窗口版/
      vaultgui.exe      双击运行
      README.md
      使用说明.txt
      data/             (空目录，首次运行自动建库)

目录名与浏览器版（密码管理器-桌面版）刻意区分：
两包若同名，同时解压到同一父目录会互相覆盖 README / 使用说明。
"""
import os
import struct
import sys
import zipfile

# 以脚本自身位置推导工程根与产物目录，避免硬编码绝对路径在迁移后失效
_HERE = os.path.dirname(os.path.abspath(__file__))
SRC = _HERE
OUT = os.path.dirname(os.path.dirname(_HERE))
# 构建产物就地放在项目内，不依赖 %TEMP%（临时目录会被系统清理，脚本会突然找不到 exe）
EXE = os.path.join(SRC, "dist-windows", "vaultgui.exe")
ICO = os.path.join(SRC, "cmd", "vaultgui", "app.ico")

PKG_ROOT = "密码管理器-原生窗口版"
ZIP_PATH = os.path.join(OUT, f"{PKG_ROOT}-Windows.zip")

README = """# 密码管理器（原生窗口版）

Windows 本地单机运行的密码管理器。**双击 exe 即用**，无需安装、无需命令行、
无需部署服务器、无需联网。

## 快速开始

1. 解压到任意目录（建议不要放 `C:\\Program Files`，那里写数据要管理员权限）
2. **双击 `vaultgui.exe`**
3. 弹出独立窗口，首次使用按提示创建主账户

关闭程序：点窗口右上角 ×，或在界面里点「退出程序」。

> 没有启动脚本，也不需要黑窗口。这就是一个普通桌面程序。

## 两种密码，务必分清

| | 登录密码 | 主密钥密码 |
|---|---|---|
| 用途 | 登录系统 | 加密 / 解密所有密码数据 |
| 丢失后果 | 无法登录 | **无法解密数据，任何人都救不回来** |

建议二者设成不同的。主密钥密码丢失 = 数据永久丢失，这是端到端加密的固有代价。

## 数据存放位置

全部数据都在 exe 同级的 `data\\` 里：

```
data\\passwords.db        主数据库（密码以 AES-256-GCM 加密存储）
data\\backups\\           自动 / 手动备份（保留最近 30 份）
data\\browser-profile\\   窗口的独立浏览器配置（可随时删除，不影响密码数据）
data\\run.log             最近一次运行的日志（排障用）
```

- **备份方式**：整个文件夹复制走即可
- **迁移**：把 `data\\` 复制到新机器的同一位置
- 每次登录会自动备份一次；也可以在界面里点「备份」手动创建
- 备份文件是**不加密的完整数据库副本**，请勿放网盘或随手分享

## 安全设计

- **加密**：AES-256-GCM 认证加密（防篡改），密文格式 `版本号(1) ‖ IV(12) ‖ Tag(16) ‖ 密文`
- **密钥派生**：Argon2id（内存 64 MB / 迭代 2 / 并行 1），抗 GPU / ASIC 暴力破解
- **主密钥不落盘**：库里只存派生参数（salt + KDF 参数），每次解锁时重新派生
- **主密钥不进浏览器**：解密由本地进程完成，页面只拿到单条明文结果
- **仅监听 127.0.0.1 随机端口**：不对外开放，局域网内其他设备无法访问
- **闲置 15 分钟自动上锁**；点「锁定」会立即抹掉页面上已显示的明文
- **独立浏览器配置**：不影响你日常浏览器的书签、密码、历史

## 界面窗口说明

界面用系统自带的 **Microsoft Edge**（或 Google Chrome）以「应用模式」承载：
- 窗口没有地址栏、工具栏、标签栏，外观与普通桌面应用一致
- 使用独立配置目录，与你日常浏览器完全隔离
- **Windows 10/11 自带 Edge，通常无需安装**；若两者都被移除，程序会弹窗提示

## 与 PHP 版 / 浏览器版的关系

数据格式完全兼容：同一个 `passwords.db` 各版本都能打开读写，密文可互相解密
（已实测双向验证：Go 写→PHP 读、PHP 写→Go 读均通过）。

从 PHP 版迁移：把旧版 `data\\passwords.db` 复制到本程序 `data\\` 即可。

## 常见问题

**Q：双击后没反应？**
先看 `data\\run.log`。最常见原因是**程序已在运行**（单实例限制）——
此时会弹窗提示，请在任务栏里找已打开的窗口，而不是重复双击。

**Q：提示「未找到可用的浏览器内核」？**
本程序借系统浏览器的渲染引擎显示界面。安装 Microsoft Edge 后重试。

**Q：换电脑怎么办？**
把整个文件夹（含 `data\\`）拷过去即可，双击 exe 就能用。

**Q：忘记主密钥密码？**
无法找回。请立刻从 `data\\backups\\` 找一份旧备份，用**当时**的主密钥密码尝试。

**Q：为什么没有启动脚本（bat）？**
不需要。exe 本身是 GUI 程序（PE Subsystem=2），双击直接出窗口。

## 系统要求

- Windows 10 / 11，64 位
- Microsoft Edge（系统自带）或 Google Chrome
- 无需 .NET、无需 VC++ 运行库、无需 Go 运行时（单文件静态编译）
- **无需联网**

## 卸载

删除整个文件夹即可。程序不写注册表、不装服务、不在系统目录留任何文件。
"""

QUICK = """密码管理器 - 原生窗口版
========================================

【启动】双击 vaultgui.exe
        直接弹出独立窗口，没有地址栏，跟普通桌面软件一样。
        没有命令行黑窗口，也不需要启动脚本。

【退出】点窗口右上角 ×，或界面上点「退出程序」。

【数据】全部在 exe 同级的 data\\ 目录里：
        data\\passwords.db      主数据库（密码已加密）
        data\\backups\\         自动备份（保留最近 30 份）

        备份 = 整个文件夹复制走。换电脑 = 整个文件夹拷过去。

【重要】两种密码不一样：
        登录密码     —— 登录用，丢了找不回登录
        主密钥密码   —— 加密全部数据，丢了数据永久打不开
        建议设成不同的，主密钥密码务必记牢或离线保存。

【安全】AES-256-GCM 加密 + Argon2id 派生密钥
        主密钥只在本地进程内存里，不进浏览器
        只监听 127.0.0.1，局域网其它设备访问不到
        闲置 15 分钟自动上锁

【排障】双击没反应，先看 data\\run.log
        若提示程序已在运行，请到任务栏找已打开的窗口。

详细说明见 README.md
"""


def verify_icon_embedded(exe_path, ico_path):
    """确认图标真的进了 exe 资源段。

    只看「编译成功」不算数：清单缺资源、段标志写错都会让图标静默丢失。
    这里三重校验 —— 资源目录登记 + 段存在 + 各尺寸图标数据逐字节在文件里。
    """
    d = open(exe_path, "rb").read()
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[lf:lf + 4] == b"PE\0\0", "不是有效 PE"
    optsz = struct.unpack_from("<H", d, lf + 20)[0]
    opt = lf + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    subsystem = struct.unpack_from("<H", d, opt + 68)[0]
    # 数据目录每项 8 字节；PE32+ 起点在 opt+112
    dd = opt + (112 if magic == 0x20B else 96)
    res_rva, res_size = struct.unpack_from("<II", d, dd + 8 * 2)

    has_rsrc = False
    nsec = struct.unpack_from("<H", d, lf + 6)[0]
    sec = lf + 24 + optsz
    for i in range(nsec):
        o = sec + 40 * i
        if d[o:o + 8].rstrip(b"\x00") == b".rsrc":
            has_rsrc = True

    ico = open(ico_path, "rb").read()
    _, _, cnt = struct.unpack_from("<HHH", ico, 0)
    embedded = 0
    for i in range(cnt):
        w, h, _c, _r, _p, _b, sz, off = struct.unpack_from("<BBBBHHII", ico, 6 + 16 * i)
        if ico[off:off + sz] in d:
            embedded += 1

    return {
        "subsystem": subsystem,
        "res_rva": res_rva,
        "res_size": res_size,
        "has_rsrc_section": has_rsrc,
        "icons_total": cnt,
        "icons_embedded": embedded,
        "ok": (subsystem == 2 and res_rva != 0 and res_size > 0
               and has_rsrc and embedded == cnt),
    }


def main() -> int:
    print("=" * 58)
    print("  构建原生窗口版交付包（纯 exe）")
    print("=" * 58)

    if not os.path.exists(EXE):
        print("缺少 exe:", EXE)
        return 1
    if not os.path.exists(ICO):
        print("缺少图标:", ICO)
        return 1

    size = os.path.getsize(EXE)
    print(f"\n[1] 产物检查")
    print(f"  exe: {size:,} 字节")

    print(f"\n[2] 图标嵌入校验")
    v = verify_icon_embedded(EXE, ICO)
    print(f"  PE Subsystem = {v['subsystem']}"
          f" {'(WINDOWS_GUI，无控制台 ✓)' if v['subsystem'] == 2 else '(有控制台 ✗)'}")
    print(f"  资源目录     = RVA 0x{v['res_rva']:x} / {v['res_size']} 字节")
    print(f"  .rsrc 段存在 = {v['has_rsrc_section']}")
    print(f"  图标数据     = {v['icons_embedded']}/{v['icons_total']} 张已嵌入")
    if not v["ok"]:
        print("  ✗ 图标校验失败，中止打包")
        return 2
    print("  ✓ 图标校验通过")

    print(f"\n[3] 打包")
    if os.path.exists(ZIP_PATH):
        os.remove(ZIP_PATH)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(EXE, f"{PKG_ROOT}/vaultgui.exe")
        zf.writestr(f"{PKG_ROOT}/README.md", README.encode("utf-8"))
        zf.writestr(f"{PKG_ROOT}/使用说明.txt",
                    QUICK.replace("\n", "\r\n").encode("gbk"))
        zf.writestr(f"{PKG_ROOT}/data/.keep", b"")

    zsize = os.path.getsize(ZIP_PATH)
    print(f"  包: {ZIP_PATH}")
    print(f"  {zsize:,} 字节（{zsize / 1048576:.2f} MB），解压约 {size / 1048576:.1f} MB")

    print(f"\n[4] 包内清单")
    names = []
    with zipfile.ZipFile(ZIP_PATH) as zf:
        for info in zf.infolist():
            names.append(info.filename)
            print(f"  {info.file_size:>10,}  {info.filename}")
        # 断言：不该再有任何 bat
        bats = [n for n in names if n.lower().endswith(".bat")]
        print(f"\n  启动脚本数量 = {len(bats)}"
              f" {'（已彻底移除 ✓）' if not bats else '（残留 ✗）'}")
        r = zf.read(f"{PKG_ROOT}/使用说明.txt").decode("gbk")
        print(f"  使用说明含「双击 bat」= {'双击 vaultgui.exe' in r}")

    ok = (not bats) and v["ok"]
    print(f"\n结果: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
