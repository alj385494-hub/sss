#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
账本自动备份 —— 对应审计建议 P1「数据库与证据链完善」里那条：
「不能只依赖 Agent 提示词要求'必须落库'，还应由程序保证数据写入成功并可追溯」。

为什么用 sqlite3 的 backup API 而不是直接拷文件：
    WAL 模式下 assets.db-wal 可能还有未 checkpoint 的页，直接 copy 会拿到不一致快照。
    sqlite3.Connection.backup() 是原子且一致的。

用法（PY 见 AGENTS §15）：
  "$PY" runs/tools/db_backup.py backup          # 备份全部靶标库 + 知识库
  "$PY" runs/tools/db_backup.py list            # 列出已有备份
  "$PY" runs/tools/db_backup.py prune           # 按策略清理旧备份
  "$PY" runs/tools/db_backup.py verify <批次>   # 校验某一批备份的完整性

保留策略：
  · 最近 KEEP_RECENT 个批次全留
  · 每天保留最新 1 个，最多 KEEP_DAYS 天
"""
import os
import shutil
import sqlite3
import sys
import time

RT = os.path.expanduser('~/.dsh/redteam')
WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEST_ROOT = os.path.join(WS, 'runs', 'backup', 'db')
KEEP_RECENT = 10
KEEP_DAYS = 7


def now_tag():
    return time.strftime('%Y%m%d-%H%M%S')


def sources():
    """返回 [(标签, 源路径)]。"""
    out = []
    eng = os.path.join(RT, 'engagements')
    if os.path.isdir(eng):
        for name in sorted(os.listdir(eng)):
            p = os.path.join(eng, name, 'assets.db')
            if os.path.isfile(p):
                out.append((name, p))
    kb = os.path.join(RT, 'knowledge.db')
    if os.path.isfile(kb):
        out.append(('_knowledge', kb))
    return out


def backup_one(src, dst):
    """一致的 SQLite 备份。返回字节数。"""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.remove(dst)
    s = sqlite3.connect(f'file:{src}?mode=ro', uri=True)
    try:
        d = sqlite3.connect(dst)
        try:
            s.backup(d)
        finally:
            d.close()
    finally:
        s.close()
    return os.path.getsize(dst)


def cmd_backup(a):
    srcs = sources()
    if not srcs:
        print('没有找到任何账本库')
        return 1
    batch = a.batch or now_tag()
    dest = os.path.join(DEST_ROOT, batch)
    print(f'备份批次 {batch} → {dest}')
    ok = 0
    fail = 0
    total = 0
    for label, src in srcs:
        dst = os.path.join(dest, label, os.path.basename(src))
        try:
            size = backup_one(src, dst)
            total += size
            ok += 1
        except Exception as e:
            print(f'  ❌ {label}: {e}')
            fail += 1
    print(f'  ✅ {ok} 个成功 / {fail} 失败，共 {total/1024/1024:.2f} MB')
    # 写一个 manifest，便于 verify
    import json
    manifest = {'batch': batch, 'at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'count': ok, 'bytes': total,
                'items': [{'label': l, 'src': s.replace(os.path.expanduser('~'), '~')} for l, s in srcs]}
    with open(os.path.join(dest, '_manifest.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    return 0 if fail == 0 else 1


def cmd_list(a):
    if not os.path.isdir(DEST_ROOT):
        print('还没有任何备份')
        return 0
    batches = sorted(d for d in os.listdir(DEST_ROOT) if os.path.isdir(os.path.join(DEST_ROOT, d)))
    print(f'共 {len(batches)} 个批次：')
    for b in batches:
        p = os.path.join(DEST_ROOT, b)
        size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(p) for f in fs)
        dbs = sum(1 for _, _, fs in os.walk(p) for f in fs if f.endswith('.db'))
        print(f'  {b}   {dbs:3} 个库   {size/1024/1024:6.2f} MB')
    return 0


def cmd_prune(a):
    if not os.path.isdir(DEST_ROOT):
        return 0
    batches = sorted(d for d in os.listdir(DEST_ROOT)
                     if os.path.isdir(os.path.join(DEST_ROOT, d)) and d[:8].isdigit())
    keep = set(batches[-KEEP_RECENT:])
    # 每天保留最新一个
    by_day = {}
    for b in batches:
        by_day.setdefault(b[:8], []).append(b)
    for day, lst in sorted(by_day.items())[-KEEP_DAYS:]:
        keep.add(lst[-1])
    removed = 0
    for b in batches:
        if b in keep:
            continue
        shutil.rmtree(os.path.join(DEST_ROOT, b), ignore_errors=True)
        print(f'  删除旧备份 {b}')
        removed += 1
    print(f'保留 {len(keep)} 个批次，删除 {removed} 个')
    return 0


def cmd_verify(a):
    batch = a.batch
    p = os.path.join(DEST_ROOT, batch) if batch else None
    if not p or not os.path.isdir(p):
        print(f'批次不存在：{batch}')
        return 2
    bad = 0
    checked = 0
    for r, _, fs in os.walk(p):
        for f in fs:
            if not f.endswith('.db'):
                continue
            fp = os.path.join(r, f)
            checked += 1
            try:
                c = sqlite3.connect(f'file:{fp}?mode=ro', uri=True)
                n = c.execute('PRAGMA integrity_check').fetchone()[0]
                c.close()
                if n != 'ok':
                    print(f'  ❌ {fp}: {n}')
                    bad += 1
            except Exception as e:
                print(f'  ❌ {fp}: {e}')
                bad += 1
    print(f'校验 {checked} 个库，{bad} 个异常')
    return 0 if bad == 0 else 1


def main():
    import argparse
    ap = argparse.ArgumentParser(description='账本自动备份')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('backup'); p.add_argument('--batch', help='自定义批次号'); p.set_defaults(f=cmd_backup)
    p = sub.add_parser('list'); p.set_defaults(f=cmd_list)
    p = sub.add_parser('prune'); p.set_defaults(f=cmd_prune)
    p = sub.add_parser('verify'); p.add_argument('batch'); p.set_defaults(f=cmd_verify)
    a = ap.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    sys.exit(a.f(a))


if __name__ == '__main__':
    main()
