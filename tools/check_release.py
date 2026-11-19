#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前一致性检查（C13-19）。

版本号必须只有一个源：工作区根 VERSION。
本脚本检查 VERSION / build 产物 / 插件 package.json / git tag / README 技能数 是否一致。

用法：
    python runs/tools/check_release.py               # 检查当前状态
    python runs/tools/check_release.py --repo runs/sss-repo
"""
import json
import os
import re
import subprocess
import sys

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OK = []
BAD = []


def ck(name, ok, detail=''):
    (OK if ok else BAD).append((name, detail))


def read_version():
    try:
        return open(os.path.join(WS, 'VERSION'), encoding='utf-8').read().strip().splitlines()[0].strip()
    except Exception as e:
        BAD.append(('VERSION 可读', str(e)))
        return None


def main():
    repo = os.path.join(WS, 'runs', 'sss-repo')
    for i, a in enumerate(sys.argv):
        if a == '--repo' and i + 1 < len(sys.argv):
            repo = sys.argv[i + 1]

    v = read_version()
    print('VERSION = %s' % v)
    print()

    # 1) VERSION 本身
    ck('VERSION 有值', bool(v), v or '空')
    ck('VERSION 符合语义化', bool(v and re.match(r'^\d+\.\d+\.\d+(-[\w.]+)*$', v)), v or '')

    # 2) 包内 VERSION
    pv = None
    try:
        pv = open(os.path.join(repo, 'VERSION'), encoding='utf-8').read().strip().splitlines()[0].strip()
    except Exception:
        pass
    ck('包内 VERSION 与源一致', pv == v, '包内=%s 源=%s' % (pv, v))

    # 3) 插件 package.json
    try:
        pkg = json.load(open(os.path.join(WS, 'runs', 'plugins', 'dsh-tool-guardrail', 'package.json'), encoding='utf-8'))
        src_plugin = pkg.get('version')
        shipped = json.load(open(os.path.join(repo, 'plugins', 'dsh-tool-guardrail', 'package.json'),
                                 encoding='utf-8')).get('version')
        ck('插件版本 源==包', src_plugin == shipped, '源=%s 包=%s' % (src_plugin, shipped))
        # 插件版本与主版本不需要相同（插件独立演进），但必须能在 README 里查到
        ck('插件版本非空', bool(src_plugin), src_plugin or '空')
    except Exception as e:
        BAD.append(('插件 package.json 可读', str(e)))

    # 4) 插件代码里的 version 字面量要和 package.json 一致
    try:
        code = open(os.path.join(WS, 'runs', 'plugins', 'dsh-tool-guardrail', 'lib', 'index.js'), encoding='utf-8').read()
        m = re.search(r"tag:\s*'plugin-loaded',\s*version:\s*'([^']+)'", code)
        code_v = m.group(1) if m else None
        pkg_v = json.load(open(os.path.join(WS, 'runs', 'plugins', 'dsh-tool-guardrail', 'package.json'),
                               encoding='utf-8')).get('version')
        ck('插件代码 version == package.json', code_v == pkg_v, '代码=%s 包=%s' % (code_v, pkg_v))
    except Exception as e:
        BAD.append(('插件代码 version 可读', str(e)))

    # 5) git tag 与 VERSION
    try:
        tags = subprocess.run(['git', 'tag'], cwd=repo, capture_output=True, text=True, timeout=60).stdout.split()
        want = 'v' + (v or '')
        ck('git tag 含 v%s' % v, want in tags, '现有 tag: %s' % (' '.join(sorted(tags)) or '(无)'))
        def vkey(t):
            nums = [int(x) for x in re.findall(r'\d+', t)]
            return nums
        latest = sorted(tags, key=vkey)[-1] if tags else None
        ck('最新 tag 与 VERSION 一致', latest == want, '最新=%s 期望=%s' % (latest, want))
    except Exception as e:
        BAD.append(('git tag 可读', str(e)))

    # 6) 技能数量（三种口径写清楚）
    try:
        sk_dir = os.path.join(repo, 'skills')
        files = [f for f in os.listdir(sk_dir) if f.endswith('.md')] if os.path.isdir(sk_dir) else []
        n_files = len(files)
        readme = open(os.path.join(repo, 'README.md'), encoding='utf-8').read()
        nums = [int(x) for x in re.findall(r'(\d+)\s*(?:个技能|个 skill)', readme)]
        ck('README 技能数与实际文件数一致', (not nums) or all(n == n_files for n in nums),
           'README 写 %s，实际 %d 个 .md' % (nums or '未写', n_files))
        ck('技能文件数 > 0', n_files > 0, '%d' % n_files)
        # manifest 口径
        mf = os.path.join(sk_dir, '_manifest.json')
        if os.path.exists(mf):
            d = json.load(open(mf, encoding='utf-8'))
            # manifest 是 {"count": N, "origin": {file: source}} —— 别把顶层 key 数当条目数
            if isinstance(d, list):
                n_mf = len(d)
            elif isinstance(d.get('origin'), dict):
                n_mf = len(d['origin'])
            elif isinstance(d.get('skills'), (list, dict)):
                n_mf = len(d['skills'])
            else:
                n_mf = d.get('count', 0)
            ck('_manifest.json 覆盖全部技能', n_mf == n_files, 'manifest=%d 实际=%d' % (n_mf, n_files))
    except Exception as e:
        BAD.append(('技能统计可读', str(e)))

    print('检查结果')
    print('=' * 58)
    for n, d in OK:
        print('  [OK] %-34s %s' % (n, d))
    for n, d in BAD:
        print('  [!!] %-34s %s' % (n, d))
    print('=' * 58)
    print('%d 通过 / %d 未通过' % (len(OK), len(BAD)))
    return 0 if not BAD else 1


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    sys.exit(main())
