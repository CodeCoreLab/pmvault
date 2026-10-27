#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""pmvault macOS 分发包打包脚本。

Windows 侧的 ``脚本-打包.py`` 产出的是 PE Subsystem=2 的 exe + bat 启动器，
在 macOS 上完全不可用（PE 格式、GBK 编码的 bat、``.syso`` 图标资源都是
Windows 专属）。macOS 侧必须产出 **Mach-O 可执行文件 + .app bundle**，
本脚本负责后者的封装：

    密码管理器-<变体>.app/
      Contents/
        Info.plist          CFBundleExecutable / 图标 / 版本号
        PkgInfo             "APPL????" 标记
        MacOS/<exe>         Mach-O 可执行文件（universal：arm64 + x86_64）
        Resources/AppIcon.icns

打包策略与 Windows 侧的差异：

| 项 | Windows | macOS |
|---|---|---|
| 产物格式 | exe（PE）+ zip | .app bundle + zip |
| 图标 | .ico 经 rsrc .syso 链入 PE 资源段 | .icns 放 Contents/Resources |
| 控制台 | -H windowsgui（无黑框） | .app 默认无终端（LSUIElement=1） |
| 启动方式 | 双击 exe | 双击 .app（首次需右键打开，见说明） |
| 权限位 | 无 | bundle 内二进制 0755，必须显式写进 zip |
| 编码 | bat + GBK + CRLF | UTF-8 说明文本，无 bat |

用法::

    python 脚本-打包-macOS.py <Mach-O 可执行文件> <变体> <输出目录>

    变体取值：native（原生窗口版 / vaultgui）、browser（桌面版 / vaultd）
"""
import os
import plistlib
import struct
import sys
import zipfile

# .app 的基本标识。identifier 必须与线上页面/未来签名保持一致，
# 改了就变成另一个应用（macOS 会当成两套权限与偏好设置）。
BUNDLE_ID = "cn.gf.pmvault"
BUNDLE_VERSION = "1.0.0"
SHORT_VERSION = "1.0.0"
MIN_SYSTEM = "11.0"

# icns 各条目类型 -> 像素尺寸。
# ic11/ic12/ic13/ic14 是 @2x 变体（同样是 PNG 编码）。
ICNS_ENTRIES = [
    ("icp4", 16),
    ("icp5", 32),
    ("icp6", 64),
    ("ic07", 128),
    ("ic08", 256),
    ("ic09", 512),
    ("ic10", 1024),
    ("ic11", 64),     # 32@2x
    ("ic12", 128),    # 64@2x
    ("ic13", 512),    # 128@2x
    ("ic14", 1024),   # 256@2x
]

VARIANTS = {
    "native": {
        "app": "密码管理器-原生窗口版.app",
        "exe": "pmvault",
        "display": "密码管理器",
        "desc": "独立应用窗口版（Edge / Chrome --app 模式承载）",
    },
    "browser": {
        "app": "密码管理器-桌面版.app",
        "exe": "pmvault",
        "display": "密码管理器",
        "desc": "浏览器版（启动后在默认浏览器中打开）",
    },
}

README_TEXT = """密码管理器（macOS 版）
====================

{desc}

系统要求
--------
* macOS {minsys} 及以上
* 原生窗口版需要已安装 Microsoft Edge 或 Google Chrome
  （检查：访��� https://www.google.com/chrome/ 或 https://www.microsoft.com/edge 下载安装）
* 浏览器版使用系统默认浏览器，无需额外安装

安装
----
1. 解压本 zip（双击即可自动解压到「下载」文件夹）
2. 把 .app 文件夹拖进「应用程序」文件夹
   （也可以放在任意位置直接双击运行，不装到 /Applications 也完全可用）
3. 首次打开若提示「无法验证开发者」或「已损坏」：
   * 在 Finder 里 **右键点击** 该 .app → 选择「打开」→ 再点「打开」
   * 或打开「系统设置 → 隐私与安全性」，在下方提示中点「仍要打开」
   * 命令行方式：xattr -dr com.apple.quarantine "密码管理器-原生窗口版.app"

卸载
----
把 .app 文件夹拖进废纸篓并删除即可。程序不写系统目录、不注册后台服务、
不安装任何驱动，删除即卸载干净。

数据存放位置
------------
* ~/Library/Application Support/PasswordManager/
  包含 passwords.db（加密后的密码库）、backups/（自动备份，保留最近 30 份）、
  run.log（最近一次运行日志，排障用）
* macOS 版不提供「便携模式」（把 data/ 放在 .app 内部会破坏代码签名），
  备份与迁移请直接复制上述目录

数据完全兼容：与 Windows 版共用同一套 passwords.db 格式，可双向读写。

安全说明
--------
* 对称加密 AES-256-GCM，主密钥仅存在于进程内存，不落盘
* 口令哈希 Argon2id，登录失败 5 次锁定 15 分钟
* 仅监听 127.0.0.1 回环地址，不对外网开放、不联网
* 闲置 15 分钟自动上锁，会话 30 分钟过期

本程序未做 Apple 公证（未购买开发者签名），
因此首次打开需要按上面的方式手动放行，属正常现象。
"""

USAGE_TEXT = """使用说明 —— 密码管理器 macOS 版
============================

1. 双击 zip 解压。
2. 右键点击 .app →「打开」→ 确认「打开」。
   （首次需手动放行；之后可直接双击启动。）
3. 首次运行会要求设置管理员密码，密码只存在本机，不会上传。
4. 数据保存在 ~/Library/Application Support/PasswordManager/，
   迁移机器时直接复制该目录即可。

常见问题
--------
Q: 提示「无法验证开发者 / 已损坏，无法打开」怎么办？
A: 右键 .app 选「打开」；或在「系统设置 → 隐私与安全性」点「仍要打开」；
   或执行 xattr -dr com.apple.quarantine "*.app"。

Q: 提示「未找到可用的浏览器内核」？
A: 原生窗口版需要 Microsoft Edge 或 Google Chrome，请先安装其一。

Q: 换电脑后密码还在吗？
A: 在旧机 data/passwords.db 拷到新机对应位置即可，数据格式与 Windows 版一致。

Q: 日志在哪？
A: data/run.log（只保留最近一次运行）。
"""


def build_icns(ico_path, out_path):
    """从 .ico 内嵌的 PNG 组装 .icns 容器。

    .icns 格式：'icns' + 总长度(uint32 BE)，随后是若干
    [类型(4B) + 长度(uint32 BE, 含 8 字节头) + 数据] 条目。
    PNG 数据直接嵌入对应类型即可，macOS 原生支持。
    """
    from PIL import Image

    im = Image.open(ico_path)
    available = {}
    for size in sorted(im.info.get("sizes", [])):
        sub = Image.open(ico_path)
        sub.size = size
        sub.load()
        available[size[0]] = sub.convert("RGBA")

    if not available:
        raise SystemExit("ico 中没有可用的 PNG 尺寸")

    base = max(available)  # 以最大尺寸为放大源
    chunks = []
    for etype, px in ICNS_ENTRIES:
        if px in available:
            img = available[px]
        else:
            src = available[base].resize((px, px), Image.LANCZOS)
            img = src
        from io import BytesIO

        buf = BytesIO()
        img.save(buf, format="PNG")
        data = buf.getvalue()
        chunks.append(struct.pack(">4sI", etype.encode("ascii"), len(data) + 8) + data)

    body = b"".join(chunks)
    with open(out_path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(body) + 8) + body)
    return out_path


def make_info_plist(variant):
    v = VARIANTS[variant]
    return {
        "CFBundleName": v["display"],
        "CFBundleDisplayName": v["display"],
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": v["exe"],
        "CFBundleIconFile": "AppIcon",
        "CFBundlePackageType": "APPL",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleShortVersionString": SHORT_VERSION,
        "CFBundleVersion": BUNDLE_VERSION,
        "CFBundleDevelopmentRegion": "zh_CN",
        "CFBundleAllowMixedLocalizations": True,
        # 桌面窗口由 Edge/Chrome 提供，我们的进程只做后台服务，
        # 不在 Dock 上留一个无意义的图标。
        "LSUIElement": True,
        "LSMinimumSystemVersion": MIN_SYSTEM,
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSSupportsAutomaticGraphicsSwitching": True,
        "NSHumanReadableCopyright": "© 广发证券 稳定性保障中心",
    }


def zip_bundle(src_dir, zip_path, arc_root):
    """把 .app 打成 zip。

    两个关键点：
    1. **arc_root 必须带 .app 目录名**：zip 内路径要是
       ``密码管理器-原生窗口版.app/Contents/...``，
       否则解压出来是一个叫 "Contents" 的散目录，Finder 认不出是应用。
    2. **必须显式写回 unix 权限位**：macOS 的「解压缩」依赖 zip 里的
       external_attr 保存权限，丢失后 .app 内的二进制会变成 0644，
       双击提示「无法执行」。
    """
    files = []
    for root, dirs, fs in os.walk(src_dir):
        for d in dirs:
            files.append(os.path.join(root, d))
        for f in fs:
            files.append(os.path.join(root, f))
    files.sort(key=lambda p: p.replace("\\", "/"))

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in files:
            rel = os.path.relpath(path, src_dir).replace("\\", "/")
            arc = arc_root + "/" + rel
            is_dir = os.path.isdir(path)
            if is_dir:
                zi = zipfile.ZipInfo(arc + "/")
                zi.external_attr = (0o755 << 16) | 0x10
                zi.create_system = 3
                z.writestr(zi, b"")
                continue
            zf = zipfile.ZipInfo(arc)
            zf.create_system = 3
            zf.compress_type = zipfile.ZIP_DEFLATED
            # 可执行文件 0755，其余 0644
            mode = 0o755 if rel.endswith("/MacOS/" + VARIANTS_CURRENT["exe"]) else 0o644
            zf.external_attr = (mode << 16)
            with open(path, "rb") as fh:
                z.writestr(zf, fh.read())


VARIANTS_CURRENT = None


def main():
    global VARIANTS_CURRENT
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    exe_path, variant, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    if variant not in VARIANTS:
        print("变体必须是 native 或 browser")
        return 2
    if not os.path.exists(exe_path):
        print("可执行文件不存在:", exe_path)
        return 1
    VARIANTS_CURRENT = VARIANTS[variant]

    v = VARIANTS[variant]
    os.makedirs(outdir, exist_ok=True)
    stage = os.path.join(outdir, v["app"])
    contents = os.path.join(stage, "Contents")
    macos_dir = os.path.join(contents, "MacOS")
    res_dir = os.path.join(contents, "Resources")
    for d in (macos_dir, res_dir):
        os.makedirs(d, exist_ok=True)

    # 可执行文件
    dst_exe = os.path.join(macos_dir, v["exe"])
    with open(exe_path, "rb") as src, open(dst_exe, "wb") as dst:
        dst.write(src.read())
    os.chmod(dst_exe, 0o755)

    # Info.plist / PkgInfo
    with open(os.path.join(contents, "Info.plist"), "wb") as f:
        plistlib.dump(make_info_plist(variant), f)
    with open(os.path.join(contents, "PkgInfo"), "w", encoding="utf-8") as f:
        f.write("APPL????")

    # 图标：从 .ico 的 PNG 组装 icns
    ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase-edgeapp", "cmd", "vaultgui", "app.ico")
    if not os.path.exists(ico):
        ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase-a", "cmd", "vaultd", "app.ico")
    if os.path.exists(ico):
        build_icns(ico, os.path.join(res_dir, "AppIcon.icns"))
    else:
        print("  ! 未找到 app.ico，跳过图标")

    # 随包说明
    with open(os.path.join(stage, "使用说明.txt"), "w", encoding="utf-8") as f:
        f.write(USAGE_TEXT)
    with open(os.path.join(stage, "README.md"), "w", encoding="utf-8") as f:
        f.write(README_TEXT.format(desc=v["desc"], minsys=MIN_SYSTEM))
    # 注意：**不在 .app 内放 data/ 目录**。
    # .app 是签名容器，内部可变数据会破坏代码签名（macOS 每次启动都校验
    # bundle 完整性），且 Gatekeeper 对被改动的 bundle 会直接判定损坏。
    # macOS 版的便携判据自然落空，数据一律走
    # ~/Library/Application Support/PasswordManager/（由 os.UserConfigDir() 提供）。

    zip_path = os.path.join(outdir, v["app"] + ".zip")
    zip_bundle(stage, zip_path, v["app"])

    print("=" * 58)
    print("  macOS 分发包打包完成")
    print("=" * 58)
    print(f"  变体    : {variant}（{v['desc']}）")
    print(f"  bundle  : {stage}")
    print(f"  zip     : {zip_path}  ({os.path.getsize(zip_path):,} 字节)")
    print(f"  可执行  : {os.path.getsize(dst_exe):,} 字节")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
