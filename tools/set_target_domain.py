#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只改台账某一行的「域名」列（不动单位名/状态/其它行），改前备份、改后全表逐格 diff 复核。

用法:
    python runs/tools/set_target_domain.py --list
    python runs/tools/set_target_domain.py --unit 某省级医院 --domain www.<客户域名>
    python runs/tools/set_target_domain.py --unit 某省级医院 --domain www.<客户域名> --dry-run

为什么不用 replace_target_row.py：那个是「整行换靶标」（单位名+域名一起换），
这里只需要纠正域名拼写，要求能证明「全表只有那一个单元格变了」。
"""
import argparse
import datetime
import io
import os
import shutil
import sys

from openpyxl import load_workbook

SRC = r"<HOME>\Desktop\域名信息汇总表.xlsx"
BAK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backup")
HEADER = ["单位名称", "域名", "IP 段", "排除项", "状态", "账号"]


def sheet_matrix(ws):
    return [[("" if c is None else str(c)) for c in row] for row in ws.iter_rows(values_only=True)]


def find_row(ws, unit):
    for r in range(2, ws.max_row + 1):
        v = ws.cell(row=r, column=1).value
        if v and unit in str(v):
            return r
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", help="单位名称（模糊匹配，命中必须唯一）")
    ap.add_argument("--domain", help="新的域名")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    if not os.path.exists(SRC):
        print("❌ 找不到台账: %s" % SRC)
        return 1
    wb = load_workbook(SRC)
    ws = wb.active

    if a.list:
        print("当前台账（%s）:" % ws.title)
        for r in range(2, ws.max_row + 1):
            u = ws.cell(row=r, column=1).value
            d = ws.cell(row=r, column=2).value
            s = ws.cell(row=r, column=5).value
            if u:
                print("  R%-3d %-30s %-32s %s" % (r, str(u)[:28], str(d or "")[:30], s or ""))
        return 0

    if not a.unit or not a.domain:
        print("用法: --unit <单位名> --domain <新域名>  |  --list")
        return 2

    # 唯一命中检查
    hits = [r for r in range(2, ws.max_row + 1)
            if ws.cell(row=r, column=1).value and a.unit in str(ws.cell(row=r, column=1).value)]
    if not hits:
        print("❌ 台账里没有含「%s」的行" % a.unit)
        return 1
    if len(hits) > 1:
        print("❌ 命中多行 %s，请给更精确的单位名" % hits)
        return 1
    row = hits[0]
    old = ws.cell(row=row, column=2).value
    print("命中: R%d  %s" % (row, ws.cell(row=row, column=1).value))
    print("域名: %r -> %r" % (old, a.domain))
    if str(old) == a.domain:
        print("已一致，无需修改")
        return 0
    if a.dry_run:
        print("(--dry-run 未写盘)")
        return 0

    before = sheet_matrix(ws)
    ws.cell(row=row, column=2).value = a.domain

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(BAK_DIR, exist_ok=True)
    bak = os.path.join(BAK_DIR, "域名信息汇总表-%s.xlsx" % stamp)
    shutil.copy2(SRC, bak)
    print("备份: %s" % bak)

    try:
        wb.save(SRC)
    except PermissionError as e:
        print("❌ 写盘失败（文件被 WPS/Excel 占用？）: %s" % e)
        print("   请关闭表格后重跑；备份仍在 %s" % bak)
        return 1

    # 全表逐格 diff：必须只有 (row, 域名列) 变
    wb2 = load_workbook(SRC)
    ws2 = wb2.active
    after = sheet_matrix(ws2)
    diffs = [(r, c) for r in range(max(len(before), len(after)))
             for c in range(len(HEADER))
             if (before[r][c] if r < len(before) and c < len(before[r]) else None)
             != (after[r][c] if r < len(after) and c < len(after[r]) else None)]
    print("全表 diff: %d 处 %s" % (len(diffs), diffs))
    ok = diffs == [(row - 1, 1)]
    print("复核: R%d 域名 = %r => %s" % (row, ws2.cell(row=row, column=2).value,
                                        "✅ 只改了这一个单元格" if ok else "❌ 有意外改动"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
