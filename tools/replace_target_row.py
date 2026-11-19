# -*- coding: utf-8 -*-
"""把桌面台账里某一行的「单位名称 / 域名」替换成新靶标（只改这一行，改前备份、改后复核）。"""
import datetime
import io
import shutil
import sys

import openpyxl

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SRC = r"<HOME>\Desktop\域名信息汇总表.xlsx"
BAK_DIR = r"<HOME>\Documents\deepseek-harness\default-workspace\runs\backup"

OLD_UNIT = "杭州诗路云科技有限公司"
NEW_UNIT = "某机器人公司"
NEW_DOMAIN = "www.<客户域名>"


def main():
    wb = openpyxl.load_workbook(SRC)
    ws = wb["Sheet1"]
    header = [("" if c.value is None else str(c.value).strip()) for c in ws[1]]
    cu = header.index("单位名称") + 1
    cd = header.index("域名") + 1
    cs = header.index("状态") + 1

    target_row = None
    for r in range(2, ws.max_row + 1):
        v = ws.cell(row=r, column=cu).value
        if v and OLD_UNIT in str(v):
            target_row = r
            break

    if target_row is None:
        print("[!] 没找到「%s」，现有单位：" % OLD_UNIT)
        for r in range(2, ws.max_row + 1):
            v = ws.cell(row=r, column=cu).value
            if v:
                print("   R%d  %s" % (r, v))
        return 2

    old_unit = ws.cell(row=target_row, column=cu).value
    old_domain = ws.cell(row=target_row, column=cd).value
    old_status = ws.cell(row=target_row, column=cs).value

    print("命中 R%d" % target_row)
    print("  单位: %r -> %r" % (old_unit, NEW_UNIT))
    print("  域名: %r -> %r" % (old_domain, NEW_DOMAIN))
    print("  状态: %r （保持不变）" % old_status)

    import os
    os.makedirs(BAK_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = os.path.join(BAK_DIR, "域名信息汇总表-%s.xlsx" % stamp)
    shutil.copy2(SRC, bak)
    print("备份: %s" % bak)

    ws.cell(row=target_row, column=cu).value = NEW_UNIT
    ws.cell(row=target_row, column=cd).value = NEW_DOMAIN
    wb.save(SRC)

    # 复核
    ws2 = openpyxl.load_workbook(SRC)["Sheet1"]
    got_unit = ws2.cell(row=target_row, column=cu).value
    got_dom = ws2.cell(row=target_row, column=cd).value
    ok = (got_unit == NEW_UNIT and got_dom == NEW_DOMAIN)
    print("复核: R%d 单位=%r 域名=%r => %s" % (target_row, got_unit, got_dom, "✅ 一致" if ok else "❌ 不一致"))

    print("\n=== 当前全表 ===")
    for r in range(1, ws2.max_row + 1):
        cells = [("" if ws2.cell(row=r, column=c).value is None else str(ws2.cell(row=r, column=c).value))
                 for c in range(1, ws2.max_column + 1)]
        if any(x.strip() for x in cells):
            print("  R%-2d | %s" % (r, " | ".join(cells)))
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(main())
