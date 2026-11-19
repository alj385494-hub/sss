#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""更新桌面《域名信息汇总表》里靶标的「状态」列。

用法:
    python update_status.py --list                        # 只看当前状态
    python update_status.py "某本地生活平台公司"    # 标记为 已测(今天)
    python update_status.py "某省属师范高校" --dry-run        # 只演练不改
    python update_status.py "某公司" --date 2026-11-12      # 指定日期
    python update_status.py "某公司" --status "已测(部分)"    # 自定义状态文本

规则:
  · 只改命中的那一行，绝不批量改（防止误伤其他靶标）
  · 写前自动备份到 runs/backup/，写后重新读取复核
  · 单位名支持模糊包含匹配，但有歧义时会列候选并退出
"""
import argparse
import datetime
import os
import shutil
import sys

def _safe_stdout():
    """Windows GBK 控制台打印 emoji 会抛 UnicodeEncodeError（写盘已成功，但看起来像失败）。
    统一改成 UTF-8 + errors=replace，确保任何终端都不会因编码中断。"""
    for stream in ("stdout", "stderr"):
        s = getattr(sys, stream, None)
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_safe_stdout()


try:
    import openpyxl
except ImportError:
    sys.exit("[!] 需要 openpyxl: pip install openpyxl")

SRC = r"<HOME>\Desktop\域名信息汇总表.xlsx"
BAK_DIR = r"<HOME>\Documents\deepseek-harness\default-workspace\runs\backup"


def load(ws_path=SRC):
    if not os.path.exists(ws_path):
        sys.exit("[!] 找不到表格: %s" % ws_path)
    wb = openpyxl.load_workbook(ws_path)
    ws = wb["Sheet1"] if "Sheet1" in wb.sheetnames else wb.active
    return wb, ws


def col_index(ws, name):
    header = [c.value for c in ws[1]]
    header = ["" if h is None else str(h).strip() for h in header]
    if name not in header:
        sys.exit("[!] 表头里没有「%s」，实际表头: %s" % (name, header))
    return header.index(name) + 1


def dump(ws, unit_col, st_col):
    print("=== 当前状态 ===")
    for r in range(2, ws.max_row + 1):
        unit = ws.cell(row=r, column=unit_col).value
        st = ws.cell(row=r, column=st_col).value
        if unit:
            print("  R%-2d %-34s %s" % (r, str(unit)[:34], "" if st is None else st))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unit", nargs="?", help="靶标单位名称（支持部分匹配）")
    ap.add_argument("--list", action="store_true", help="只列当前状态")
    ap.add_argument("--dry-run", action="store_true", help="只演练，不写盘")
    ap.add_argument("--date", default=None, help="日期 YYYY-MM-DD，默认今天")
    ap.add_argument("--status", default=None, help="自定义状态文本（默认 已测(日期)）")
    ap.add_argument("--file", default=SRC, help="表格路径")
    a = ap.parse_args()

    wb, ws = load(a.file)
    cu = col_index(ws, "单位名称")
    cs = col_index(ws, "状态")

    if a.list or not a.unit:
        dump(ws, cu, cs)
        if not a.unit:
            print("\n用法: python update_status.py \"单位名称\"")
        return 0

    key = a.unit.strip()
    hits = []
    for r in range(2, ws.max_row + 1):
        unit = ws.cell(row=r, column=cu).value
        if unit and key in str(unit):
            hits.append((r, str(unit).strip()))

    # 精确同名优先：避免「某高校」同时命中「某大学附属医院」
    exact = [h for h in hits if h[1] == key]
    if exact:
        hits = exact

    if not hits:
        print("[!] 没匹配到「%s」。现有单位：" % key)
        dump(ws, cu, cs)
        return 2
    if len(hits) > 1:
        print("[!] 匹配到 %d 行，有歧义，请写更完整的名称：" % len(hits))
        for r, u in hits:
            print("    R%d  %s" % (r, u))
        return 3

    row, unit = hits[0]
    date = a.date or datetime.date.today().strftime("%Y-%m-%d")
    new = a.status if a.status else "已测(%s)" % date
    old = ws.cell(row=row, column=cs).value

    print("命中: R%d  %s" % (row, unit))
    print("状态: %r -> %r" % (old, new))

    if a.dry_run:
        print("(--dry-run 未写盘)")
        return 0

    os.makedirs(BAK_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = os.path.join(BAK_DIR, "域名信息汇总表-%s.xlsx" % stamp)
    shutil.copy2(a.file, bak)
    print("备份: %s" % bak)

    ws.cell(row=row, column=cs).value = new
    wb.save(a.file)

    # 复核
    wb2, ws2 = load(a.file)
    got = ws2.cell(row=row, column=cs).value
    print("复核: R%d 状态 = %r  => %s" % (row, got, "OK 一致" if got == new else "FAIL 不一致"))
    dump(ws2, cu, cs)
    return 0 if got == new else 4


if __name__ == "__main__":
    sys.exit(main())
