#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成程序图标（多尺寸 ICO），并包装成 Go 可链接的 .syso 资源。

为什么要做：去掉 bat 后用户直接双击 exe，桌面/任务栏/资源管理器里显示的就是
这个 exe 的图标。没有图标资源时 Windows 会显示一个空白默认图标，比 bat 看着更简陋。

做法：
  1. 用 PIL 画一枚盾牌+钥匙孔的图标（不依赖外部素材，纯代码生成，可复现）
  2. 存成多尺寸 ICO（16/24/32/48/64/128/256）
  3. 生成 .syso（COFF 资源对象），Go 链接时自动并入 exe
     —— .syso 采用标准 PE 资源段结构，无需 windres / gcc
"""
import os
import struct
import sys

from PIL import Image, ImageDraw

# 以脚本自身位置推导工程根，避免硬编码绝对路径在迁移后失效
_HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(_HERE, "phase-edgeapp", "cmd", "vaultgui")
ICO_PATH = os.path.join(OUT_DIR, "app.ico")
SYSO_PATH = os.path.join(OUT_DIR, "rsrc_windows_amd64.syso")

# 支持指定目标目录：两个版本（phase-a / phase-edgeapp）共用同一图标
# 用法：python 脚本-生成图标.py [目标目录]
if len(sys.argv) > 1:
    OUT_DIR = sys.argv[1]
    ICO_PATH = os.path.join(OUT_DIR, "app.ico")
    SYSO_PATH = os.path.join(OUT_DIR, "rsrc_windows_amd64.syso")

SIZES = [16, 24, 32, 48, 64, 128, 256]

# 品牌绿（与界面 --brand 一致：浅色主题 #2f7d57）
BRAND = (47, 125, 87, 255)
BRAND_DARK = (38, 105, 74, 255)
WHITE = (255, 255, 255, 255)


def draw_icon(size):
    """画一枚盾牌，中间开钥匙孔。按尺寸等比缩放，小图标减少细节。"""
    # 4x 超采样后缩小，边缘更干净
    s = size * 4
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 盾牌轮廓：上宽下尖
    pad = s * 0.08
    top = pad
    bottom = s - pad
    left = pad
    right = s - pad
    midx = s / 2

    # 上半部矩形 + 下半部收尖
    shoulder = top + (bottom - top) * 0.52
    shield = [
        (left, top + (bottom - top) * 0.06),
        (right, top + (bottom - top) * 0.06),
        (right, shoulder),
        (midx, bottom),
        (left, shoulder),
    ]
    d.polygon(shield, fill=BRAND)

    # 内层高光（稍微内缩，营造厚度感）
    inset = s * 0.055
    d.polygon([
        (left + inset, top + (bottom - top) * 0.06 + inset),
        (right - inset, top + (bottom - top) * 0.06 + inset),
        (right - inset, shoulder),
        (midx, bottom - inset * 1.6),
        (left + inset, shoulder),
    ], fill=BRAND_DARK)

    # 钥匙孔：小圆 + 梯形下摆
    if size >= 24:
        kr = s * 0.115          # 圆半径
        kcy = s * 0.40          # 圆中心 y
        d.ellipse([midx - kr, kcy - kr, midx + kr, kcy + kr], fill=WHITE)
        stem_top = kcy + kr * 0.55
        stem_bot = s * 0.70
        hw_top = kr * 0.52
        hw_bot = kr * 0.86
        d.polygon([
            (midx - hw_top, stem_top),
            (midx + hw_top, stem_top),
            (midx + hw_bot, stem_bot),
            (midx - hw_bot, stem_bot),
        ], fill=WHITE)
    else:
        # 16px 太小，钥匙孔细节会糊成一团，改用简单圆点
        kr = s * 0.16
        kcy = s * 0.42
        d.ellipse([midx - kr, kcy - kr, midx + kr, kcy + kr], fill=WHITE)

    return img.resize((size, size), Image.LANCZOS)


def build_ico():
    """写多尺寸 ICO。ICO 目录项允许内嵌 PNG（Vista+ 支持）。"""
    imgs = [draw_icon(n) for n in SIZES]
    pngs = []
    for im in imgs:
        from io import BytesIO
        b = BytesIO()
        im.save(b, format="PNG")
        pngs.append(b.getvalue())

    header = struct.pack("<HHH", 0, 1, len(SIZES))  # reserved, type=1(icon), count
    entries = b""
    offset = 6 + 16 * len(SIZES)
    datas = b""
    for n, png in zip(SIZES, pngs):
        w = 0 if n >= 256 else n     # 0 表示 256
        h = 0 if n >= 256 else n
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
        datas += png
    with open(ICO_PATH, "wb") as f:
        f.write(header + entries + datas)
    return len(header + entries + datas)


def build_syso():
    """生成 COFF 目标文件，内含 RT_GROUP_ICON + RT_ICON 资源。

    结构依据 PE/COFF 规范手工拼装，避免引入 windres（本机无 mingw）。
    优点：纯 Python 生成，可复现；Go 链接器会自动把 .syso 并入。
    """
    with open(ICO_PATH, "rb") as f:
        ico = f.read()

    # 解析 ICO
    _, _, count = struct.unpack_from("<HHH", ico, 0)
    entries = []
    for i in range(count):
        off = 6 + 16 * i
        w, h, colors, res, planes, bits, size, dataoff = struct.unpack_from(
            "<BBBBHHII", ico, off)
        entries.append({
            "w": w, "h": h, "colors": colors, "planes": planes,
            "bits": bits, "size": size, "data": ico[dataoff:dataoff + size],
        })

    # ---- 资源段数据布局 ----
    # 三层目录（TYPE -> NAME -> LANG）：
    #   每层目录头 16 字节（Characteristics/TimeDateStamp/Major/Minor/Named/Id 计数）
    #   每个目录项 8 字节（Name/ID 4 字节 + OffsetToData 4 字节）
    n_icons = len(entries)
    ENT = 8                      # 目录项大小，注意不是 16
    HDR = 16                     # 目录头大小

    def dir_entry(name_id, offset_to_data):
        # NameID(4) + DataOffset(4)，后 4 字节高位置 1 表示指向子目录
        return struct.pack("<II", name_id, offset_to_data)

    off_layer1 = 0
    off_layer2_icon = off_layer1 + HDR + ENT * 2            # 层1: 2 个类型
    off_layer2_group = off_layer2_icon + HDR + ENT * n_icons
    off_layer3_icon = off_layer2_group + HDR + ENT * 1
    off_layer3_group = off_layer3_icon + ENT * n_icons
    off_data = off_layer3_group + ENT * 1

    # 先算各 ICON 数据偏移
    icon_offsets = []
    cur = off_data
    for e in entries:
        icon_offsets.append(cur)
        cur += e["size"]
    # 组图标数据（GRPICONDIR）
    grp_offset = cur

    # 构造 GRPICONDIR：头 6 字节 + 每项 14 字节
    grp = struct.pack("<HHH", 0, 1, n_icons)
    for i, e in enumerate(entries, start=1):
        grp += struct.pack("<BBBBHHIH", e["w"], e["h"], e["colors"], 0,
                           e["planes"], e["bits"], e["size"], i)
    grp_size = len(grp)

    blob = bytearray()
    # ---- 层1 ----
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2)          # 目录头：2 个命名项
    blob += dir_entry(3, 0x80000000 | off_layer2_icon)         # RT_ICON
    blob += dir_entry(14, 0x80000000 | off_layer2_group)       # RT_GROUP_ICON
    # ---- 层2：RT_ICON ----
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, n_icons)
    for i in range(1, n_icons + 1):
        blob += dir_entry(i, 0x80000000 | (off_layer3_icon + 16 * (i - 1)))
    # ---- 层2：RT_GROUP_ICON ----
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    blob += dir_entry(1, 0x80000000 | off_layer3_group)
    # ---- 层3：各 ICON 的 LANG 项 ----
    for i in range(n_icons):
        blob += struct.pack("<II", 0x0409, icon_offsets[i])     # 1033 = en-us
    # ---- 层3：GROUP 的 LANG 项 ----
    blob += struct.pack("<II", 0x0409, grp_offset)

    assert len(blob) == off_data, f"目录区长度不符: {len(blob)} != {off_data}"

    # ---- 资源数据 ----
    for e in entries:
        blob += e["data"]
    blob += grp

    res_data = bytes(blob)

    # ---- COFF 目标文件 ----
    # 单个 .rsrc 段，含标准的 ResourceDirectory 结构
    section_name = b".rsrc\0\0\0"
    # IMAGE_SECTION_HEADER 40 字节
    # VirtualSize / VirtualAddress / SizeOfRawData / PointerToRawData /
    # PointerToRelocations / PointerToLinenumbers / NumberOfRelocations /
    # NumberOfLinenumbers / Characteristics
    # Characteristics 必须是 CNT_INITIALIZED_DATA | MEM_READ（0x40000040）。
    # 不能带 MEM_WRITE：Go 链接器 loadpe 按 "CNT_INIT | MEM_READ | MEM_WRITE" 组合
    # 把段判为 .data（SNOPTRDATA），那样 .rsrc 不会被登记到资源目录表，
    # exe 里虽然有个 .rsrc 段但 RVA=0，Windows 不认，图标等于没加。
    characteristics = 0x40000040  # CNT_INITIALIZED_DATA | MEM_READ

    header_size = 20  # COFF 文件头
    sec_header_size = 40
    raw_ptr = header_size + sec_header_size

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,                 # Machine = AMD64
        1,                      # NumberOfSections
        0,                      # TimeDateStamp
        0,                      # PointerToSymbolTable
        0,                      # NumberOfSymbols
        sec_header_size,        # SizeOfOptionalHeader（目标文件应为 0，但保持 40 让对齐可算）
        0,                      # Characteristics
    )
    # 修正：目标文件 SizeOfOptionalHeader 必须为 0，raw_ptr 用 20+40 仍成立（Go 按此读取）
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)

    sec = struct.pack(
        "<8sIIIIIIHHI",
        section_name,
        len(res_data),          # VirtualSize
        0,                      # VirtualAddress
        len(res_data),          # SizeOfRawData
        raw_ptr,                # PointerToRawData
        0,                      # PointerToRelocations
        0,                      # PointerToLinenumbers
        0,                      # NumberOfRelocations
        0,                      # NumberOfLinenumbers
        characteristics,
    )

    out = coff + sec + res_data
    with open(SYSO_PATH, "wb") as f:
        f.write(out)
    return len(out), len(res_data)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    ico_size = build_ico()
    print(f"ICO:  {ICO_PATH}  ({ico_size:,} 字节, {len(SIZES)} 种尺寸)")
    syso_total, res_size = build_syso()
    print(f"SYSO: {SYSO_PATH}  ({syso_total:,} 字节，资源区 {res_size:,} 字节)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
