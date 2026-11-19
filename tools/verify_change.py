#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
改动生效检测 —— 专治「改完以为好了，其实没生效」。

背景：2026-11 反复出现同一类事故——
  · redteam_cleanup 报 "store.listCleanup is not a function"，查了 4 次才发现是进程内旧版模块
  · DEFAULT_PROMPTS 改了不重启，角色提示词还是旧的
  · 改完只看文件内容，从没验证"运行时读到的到底是哪一版"

核心区分：
  A. 立即生效（读文件型）：AGENTS.md / 技能 *.md / 派活模板 / 脚本 —— 改完即生效，但**要确认内容真的进去了**
  B. 需要重启（进程内模块 / 启动时加载）：插件 lib/*.js、cordis.patch.yml、presets/*.yml、
     DEFAULT_PROMPTS、各靶标 agents/*.md —— 改完不重启 = 没改

用法（PY 见 AGENTS §15）：
  "$PY" runs/tools/verify_change.py restart        # ★最常用：列出"改了但很可能没生效"的文件
  "$PY" runs/tools/verify_change.py file <路径> [--must-contain "关键串"] [--syntax py|js|json|yml]
  "$PY" runs/tools/verify_change.py skill <技能名>  # 检查技能文件存在 + 关键节 + 是否可读
  "$PY" runs/tools/verify_change.py all            # restart + 关键载体冒烟
"""
import argparse
import json
import os
import subprocess
import sys
import time

DSH_HOME = os.path.expanduser('~/.dsh')
PROFILE = os.path.join(DSH_HOME, 'profiles', 'desktop')

# 分类：进程内 / 启动时加载 → 改完必须重启
RESTART_PATTERNS = [
    ('插件 lib', os.path.join(PROFILE, 'node_modules')),
    ('插件 vendor', os.path.join(PROFILE, 'vendor')),
    ('profile 配置', PROFILE),
]

# 立即生效（读文件型）——只检查内容，不需要重启
IMMEDIATE = [
    ('AGENTS.md', 'AGENTS.md'),
    ('OPERATING-MODEL.md', 'OPERATING-MODEL.md'),
    ('派活模板', os.path.join('runs', 'notes', '派活模板-技能随派.md')),
    ('插件改动日志', os.path.join('runs', 'notes', '插件改动日志.md')),
    ('state.py', os.path.join('runs', 'tools', 'state.py')),
    ('卷宗模板', os.path.join('runs', 'tools', 'review', '卷宗模板.md')),
]

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def dsh_started_at():
    """拿 DSH 进程的启动时间（取最新的那个）。拿不到返回 None。

    为什么取最新：Electron 会留多个进程，旧的可能是残留僵尸（实测一次重启后同时存在
    11:50:47 和 11:57:31 两批，取最老会误报"没重启"）。最新那个才代表当前加载的代码。

    坑（实测）：PowerShell 默认把 StartTime 格式化成中文本地化形式
    （`2026年11月19日 9:59:02`），直接 strptime 会失败。必须显式 ToString 成 ISO。
    """
    names = ['DeepSeek Harness', 'node']
    best = None
    for nm in names:
        # 显式指定格式，避免本地化
        ps = ("Get-Process -Name '%s' -ErrorAction SilentlyContinue | "
              "Sort-Object StartTime | Select-Object -Last 1 | "
              "ForEach-Object { $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') }") % nm
        try:
            out = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                                 capture_output=True, text=True, timeout=25)
        except Exception:
            continue
        for line in (out.stdout or '').splitlines():
            line = line.strip()
            if len(line) < 19:
                continue
            try:
                t = time.mktime(time.strptime(line[:19], '%Y-%m-%d %H:%M:%S'))
            except ValueError:
                continue
            if best is None or t < best:
                best = t
            break
    return best


def walk(root, exts):
    out = []
    if not os.path.isdir(root):
        return out
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__', 'node_modules', '.cache')]
        for f in files:
            if any(f.endswith(e) for e in exts):
                out.append(os.path.join(base, f))
    return out


def cmd_restart(a):
    started = dsh_started_at()
    print('=' * 68)
    if started:
        print(f'DSH（node）启动时间：{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))}')
    else:
        print('DSH 启动时间：取不到（下面按 mtime 从新到旧列出，需人工判断）')
    print('=' * 68)

    suspects = []
    targets = [
        (os.path.join(PROFILE, 'node_modules'), ('.js', '.mjs', '.cjs', '.yml', '.yaml', '.json')),
        (os.path.join(PROFILE, 'vendor'), ('.js', '.mjs', '.cjs', '.yml', '.yaml', '.json')),
    ]
    for root, exts in targets:
        for f in walk(root, exts):
            try:
                m = os.path.getmtime(f)
            except OSError:
                continue
            if started and m > started:
                suspects.append((m, f))

    # 角色提示词（启动时从 DEFAULT_PROMPTS 生成，改基准后必须同步 + 重启）
    engdir = os.path.join(DSH_HOME, 'redteam', 'engagements')
    if os.path.isdir(engdir):
        for e in os.listdir(engdir):
            ad = os.path.join(engdir, e, 'agents')
            if not os.path.isdir(ad):
                continue
            for f in os.listdir(ad):
                if not f.endswith('.md') or '.bak' in f:
                    continue
                p = os.path.join(ad, f)
                try:
                    m = os.path.getmtime(p)
                except OSError:
                    continue
                if started and m > started:
                    suspects.append((m, p))

    if not suspects:
        if started:
            print('✅ 没有「启动后被修改」的进程内文件 —— 不需要重启。')
        else:
            print('⚠️  取不到启动时间，无法判定。请人工确认是否重启过。')
        return

    suspects.sort(reverse=True)
    print(f'⚠️  {len(suspects)} 个文件在 DSH 启动后被修改 → **这些改动很可能没生效，需要重启**\n')
    shown = 0
    for m, f in suspects:
        if shown >= 40:
            print(f'   …（共 {len(suspects)} 个，仅显示最近 40 个）')
            break
        rel = f.replace(os.path.expanduser('~'), '~')
        print(f'   {time.strftime("%m-%d %H:%M", time.localtime(m))}  {rel}')
        shown += 1
    print('\n处置：完全退出 DSH（含托盘）重启，然后重跑本命令确认输出为 ✅。')


def check_syntax(path, kind):
    if kind == 'py':
        import py_compile
        py_compile.compile(path, doraise=True)
        return 'py_compile OK'
    if kind == 'json':
        with open(path, 'r', encoding='utf-8') as f:
            json.load(f)
        return 'json OK'
    if kind in ('js', 'mjs'):
        node = os.path.join(os.path.expanduser('~'), '.dsh', 'dsh-runtimes', 'dsh-primary-runtime',
                            'dependencies', 'node', 'bin', 'node.exe')
        if not os.path.exists(node):
            return 'node 不存在，跳过'
        r = subprocess.run([node, '--check', path], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).strip()[:400])
        return 'node --check OK'
    if kind == 'yml':
        try:
            import yaml  # 可能没装
        except ImportError:
            return 'yml（无 yaml 库，跳过语法，仅查关键字）'
        with open(path, 'r', encoding='utf-8') as f:
            yaml.safe_load(f)
        return 'yaml OK'
    return '未检查'


def cmd_file(a):
    p = a.path
    if not os.path.isabs(p):
        p = os.path.join(WS, p)
    print(f'文件：{p}')
    if not os.path.exists(p):
        print('❌ 不存在'); sys.exit(2)
    size = os.path.getsize(p)
    mt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(p)))
    print(f'大小：{size} B   修改：{mt}')

    ok = True
    if a.syntax:
        try:
            print(f'语法：✅ {check_syntax(p, a.syntax)}')
        except Exception as e:
            print(f'语法：❌ {e}'); ok = False

    if a.must_contain:
        with open(p, 'r', encoding='utf-8', errors='replace') as f:
            body = f.read()
        for kw in a.must_contain:
            hit = kw in body
            print(f'关键串 {kw!r}：{"✅ 命中" if hit else "❌ 未命中"}')
            if not hit:
                ok = False

    # 是否属于"需重启"类型
    rel = os.path.abspath(p).replace(os.path.expanduser('~'), '~')
    need_restart = rel.startswith('~/.dsh/profiles') and (
        '/node_modules/' in rel or '/vendor/' in rel or rel.endswith('.yml'))
    if need_restart:
        started = dsh_started_at()
        if started:
            newer = os.path.getmtime(p) > started
            print(f'生效方式：**需重启**（进程内模块）')
            print(f'当前状态：{"⚠️ 文件比进程新 → 尚未生效" if newer else "✅ 文件早于进程启动 → 已加载"}')
            if newer:
                ok = False
        else:
            print('生效方式：**需重启**（启动时间取不到，请人工确认）')
    else:
        print('生效方式：立即生效（读文件型）')

    print('\n结论：' + ('✅ 通过' if ok else '❌ 有问题，见上'))
    sys.exit(0 if ok else 1)


def cmd_skill(a):
    p = os.path.join(DSH_HOME, 'skills', a.name)
    if not p.endswith('.md'):
        p += '.md'
    print(f'技能：{p}')
    if not os.path.exists(p):
        print('❌ 不存在'); sys.exit(2)
    with open(p, 'r', encoding='utf-8') as f:
        body = f.read()
    print(f'大小：{len(body)} 字符')
    fm = body.startswith('---')
    print(f'front-matter：{"✅" if fm else "❌ 缺失（可能不会被技能目录收录）"}')
    if fm:
        head = body.split('---', 2)[1] if body.count('---') >= 2 else ''
        for k in ('name', 'description'):
            print(f'  {k}：{"✅" if (k + ":") in head else "❌"}')
        if 'enabled:' in head:
            en = [l for l in head.splitlines() if l.strip().startswith('enabled:')]
            print(f'  enabled：{en[0].strip() if en else "未写（默认 true）"}')
    if a.must_contain:
        for kw in a.must_contain:
            print(f'关键串 {kw!r}：{"✅" if kw in body else "❌"}')
    print('\n生效方式：立即生效（skill 工具每次读取文件）')


def cmd_all(a):
    cmd_restart(a)
    print('\n' + '=' * 68)
    print('关键载体冒烟')
    print('=' * 68)
    checks = [
        ('AGENTS.md 有 §34', 'AGENTS.md', '## 34.'),
        ('state.py 有 why', os.path.join('runs', 'tools', 'state.py'), 'def cmd_why'),
        ('派活模板 7.3', os.path.join('runs', 'notes', '派活模板-技能随派.md'), '7.3 指令数据分离'),
        ('派活模板 7.4', os.path.join('runs', 'notes', '派活模板-技能随派.md'), '7.4 挂起式提问'),
        ('卷宗模板存在', os.path.join('runs', 'tools', 'review', '卷宗模板.md'), '复核者填写区'),
        ('技能 finding-review', os.path.join(DSH_HOME, 'skills', 'finding-review.md'), '独立复核'),
    ]
    bad = 0
    for label, rel, kw in checks:
        p = rel if os.path.isabs(rel) else os.path.join(WS, rel)
        if not os.path.exists(p):
            print(f'  ❌ {label}：文件不存在'); bad += 1; continue
        with open(p, 'r', encoding='utf-8', errors='replace') as f:
            body = f.read()
        print(f'  {"✅" if kw in body else "❌"} {label}')
        if kw not in body:
            bad += 1
    print(f'\n冒烟：{"✅ 全部通过" if bad == 0 else f"❌ {bad} 项未通过"}')



# ---------------- 规则库预算与体检 ----------------

# 规则库没有上限。文件随使用必然增长，卡上限等于封杀。
# 这里只做**趋势记录 + 体检**，减负由「后勤智能体」按用户命令执行（见 runs/notes/规则库维护SOP.md）。
HISTORY = os.path.join(WS, 'runs', 'state', 'agents-size-history.json')


def _sections(text):
    """按 ## N. 切节，返回 [(序号, 标题, 正文)]。"""
    import re
    out = []
    for m in re.finditer(r'(?m)^## (\d+)\.\s*(.+)$', text):
        start = m.start()
        nxt = text.find(chr(10) + '## ', m.end())
        end = nxt if nxt > 0 else len(text)
        out.append((m.group(1), m.group(2).strip(), text[start:end]))
    return out


def cmd_budget(a):
    path = os.path.join(WS, 'AGENTS.md')
    text = open(path, encoding='utf-8').read()
    n = len(text)
    print('=' * 68)
    print(f'AGENTS.md  {n:,} 字符 · {text.count(chr(10)) + 1} 行')
    print('=' * 68)

    # 趋势（不设上限，只看增长）
    hist = []
    if os.path.exists(HISTORY):
        try:
            hist = json.load(open(HISTORY, encoding='utf-8'))
        except Exception:
            hist = []
    today = time.strftime('%Y-%m-%d')
    prev = [h for h in hist if h.get('date') != today]
    if prev:
        last = prev[-1]
        delta = n - int(last.get('chars', n))
        arrow = '↑' if delta > 0 else ('↓' if delta < 0 else '=')
        print(f'上次（{last.get("date")}）：{int(last.get("chars", 0)):,} → 本次 {n:,}  {arrow}{abs(delta):,}')
    else:
        print('（首次记录，无历史对比）')
    hist = [h for h in hist if h.get('date') != today]
    hist.append({'date': today, 'chars': n, 'sections': len(_sections(text))})
    hist = hist[-60:]
    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    json.dump(hist, open(HISTORY, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('（已记入 Trend 趋势文件，不设上限——文件随使用增长是正常的，减负由后勤智能体按需执行）')

    secs = _sections(text)
    print(f'\n章节数：{len(secs)}')
    print('\n【最占地方的 6 节】')
    for num, title, body in sorted(secs, key=lambda x: -len(x[2]))[:6]:
        print(f'  §{num:>2}  {len(body):6,} 字符 ({len(body)/n*100:4.1f}%)  {title[:40]}')

    # 重复长句检测
    import re
    print('\n【疑似重复的长句】（同一句话出现 ≥2 次 = 该合并）')
    sents = {}
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 22 or line.startswith('#') or line.startswith('|') or line.startswith('`'):
            continue
        key = re.sub(r'\s+', '', line)
        sents.setdefault(key, []).append(line)
    dups = [(k, v) for k, v in sents.items() if len(v) >= 2]
    if not dups:
        print('  ✅ 没发现重复长句')
    else:
        for k, v in dups[:6]:
            print(f'  ×{len(v)}  {v[0][:64]}')

    # 失效引用
    print('\n【失效章节引用】')
    exist = {n for n, _, _ in secs}
    bad = sorted({m for m in re.findall(r'§(\d+)', text) if m not in exist})
    if bad:
        print('  ❌ 引用了不存在的章节: ' + ', '.join('§' + b for b in bad))
        print('     （删节后必须同步改引用，否则指向空气）')
    else:
        print('  ✅ 所有 §N 引用都指向存在的章节')


def main():
    ap = argparse.ArgumentParser(description='改动生效检测')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('restart'); p.set_defaults(f=cmd_restart)
    p = sub.add_parser('file'); p.add_argument('path'); p.add_argument('--must-contain', nargs='+'); p.add_argument('--syntax', choices=['py', 'js', 'mjs', 'json', 'yml']); p.set_defaults(f=cmd_file)
    p = sub.add_parser('skill'); p.add_argument('name'); p.add_argument('--must-contain', nargs='+'); p.set_defaults(f=cmd_skill)
    p = sub.add_parser('all'); p.set_defaults(f=cmd_all)
    p = sub.add_parser('budget'); p.set_defaults(f=cmd_budget)
    a = ap.parse_args()
    a.f(a)


if __name__ == '__main__':
    main()
