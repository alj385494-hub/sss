#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
状态持久化 —— 靶标工作状态的单一真源。

问题：DSH 重启、上下文压缩后，"下一步做什么 / 卡在哪 / 试过什么"全丢，
     每次都要手写"接班说明"。这个文件把状态落到磁盘。

用法（PY 见 AGENTS §15）：
  "$PY" runs/tools/state.py list                        # 所有有状态的靶标
  "$PY" runs/tools/state.py show 某师范高校            # 打印可读状态（派活前必跑，粘进任务）
  "$PY" runs/tools/state.py init 某师范高校 --domain jpkc.<客户域名>
  "$PY" runs/tools/state.py set 某师范高校 --stage 深挖 --next "验证 S2-045"
  "$PY" runs/tools/state.py set 某师范高校 --blocked "<IP>/16 整段封出口"
  "$PY" runs/tools/state.py hypo 某师范高校 --id H1 --fingerprint "Beangle EAMS/Struts2" \
        --cves "S2-045,S2-016" --verify "nuclei -tags struts" --fail "全部 302 到登录页"
  "$PY" runs/tools/state.py hypo 某师范高校 --id H1 --state 排除 --reason "封禁未到执行"
  "$PY" runs/tools/state.py tested 某师范高校 --what "Ghostcat AJP 8009" --result "端口未开" --verdict 排除
  "$PY" runs/tools/state.py budget 某师范高校 --used 13 --limit 60
  "$PY" runs/tools/state.py close 某师范高校         # 收口：标记本轮结束

设计原则：
  - 单个 JSON 文件，人可读、机器可解析。
  - 每次写入自动带 updated_at 和 revision 自增，便于判断新鲜度。
  - 不改已存在字段以外的任何东西（load → 改 → dump，保留未知字段）。
"""
import argparse
import json
import os
import sys
import time

# Windows 默认控制台是 GBK，中文会乱码（实测：不设 PYTHONIOENCODING 时输出 `�� 1 ��`）。
# 在脚本里强制 UTF-8，避免依赖调用方设环境变量。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8')
    except Exception:
        pass

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'state')
STATE_DIR = os.path.normpath(STATE_DIR)

HYPO_STATES = ['未决', '证实', '排除', 'blocked']
VERDICTS = ['证实', '排除']


def now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%S%z')


def path_of(target):
    safe = target.replace('/', '_').replace('\\', '_').strip()
    return os.path.join(STATE_DIR, safe + '.json')


def load(target):
    p = path_of(target)
    if not os.path.exists(p):
        return None
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def save(target, st):
    os.makedirs(STATE_DIR, exist_ok=True)
    st['updated_at'] = now_iso()
    st['revision'] = int(st.get('revision', 0)) + 1
    p = path_of(target)
    tmp = p + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)
    return p


def new_state(target, domain=''):
    return {
        'target': target,
        'domain': domain,
        'stage': '未开始',
        'next_action': '',
        'blocked_by': [],
        'hypotheses': [],
        'tested': [],
        'budget': {'used': 0, 'limit': 0},
        'rounds': [],
        'why_log': [],
        'notes': '',
        'created_at': now_iso(),
        'updated_at': now_iso(),
        'revision': 0,
    }


def require(target):
    st = load(target)
    if st is None:
        print(f'[!] 还没有状态文件：{path_of(target)}', file=sys.stderr)
        print(f'    先跑：state.py init "{target}" --domain <主域>', file=sys.stderr)
        sys.exit(2)
    return st


# ---------------- 命令 ----------------

def cmd_init(a):
    p = path_of(a.target)
    if os.path.exists(p) and not a.force:
        print(f'已存在，未覆盖：{p}（要重置加 --force）')
        return
    save(a.target, new_state(a.target, a.domain))
    print(f'✅ 初始化：{p}')


def cmd_set(a):
    st = require(a.target)
    ch = []
    if a.stage is not None:
        st['stage'] = a.stage; ch.append('stage')
    if a.next is not None:
        st['next_action'] = a.next; ch.append('next')
    if a.domain is not None:
        st['domain'] = a.domain; ch.append('domain')
    if a.notes is not None:
        st['notes'] = a.notes; ch.append('notes')
    if a.add_blocked:
        for b in a.add_blocked:
            if b not in st['blocked_by']:
                st['blocked_by'].append(b)
        ch.append('blocked_by+')
    if a.clear_blocked:
        st['blocked_by'] = []
        ch.append('blocked_by=')
    if not ch:
        print('没有要改的字段（用 --stage/--next/--notes/--add-blocked/--clear-blocked）')
        return
    save(a.target, st)
    print(f'✅ 已更新 {" ".join(ch)} → {path_of(a.target)}')


def cmd_hypo(a):
    st = require(a.target)
    hid = a.id
    if not hid:
        print('[!] 需要 --id', file=sys.stderr); sys.exit(2)
    h = next((x for x in st['hypotheses'] if x.get('id') == hid), None)
    if h is None:
        h = {'id': hid, 'fingerprint': '', 'cves': [], 'verify_method': '',
             'fail_signal': '', 'state': '未决', 'reason': ''}
        st['hypotheses'].append(h)
        created = True
    else:
        created = False
    for f, dest in (('fingerprint', 'fingerprint'), ('verify', 'verify_method'), ('fail', 'fail_signal')):
        v = getattr(a, f)
        if v is not None:
            h[dest] = v
    if a.cves is not None:
        h['cves'] = [x.strip() for x in a.cves.split(',') if x.strip()]
    if a.state is not None:
        if a.state not in HYPO_STATES:
            print(f'[!] state 只能是 {HYPO_STATES}', file=sys.stderr); sys.exit(2)
        h['state'] = a.state
    if a.reason is not None:
        h['reason'] = a.reason
    save(a.target, st)
    print(f'✅ 假设 {hid} {"新建" if created else "更新"}：{h["state"]} · {h["fingerprint"][:50]}')


def cmd_tested(a):
    st = require(a.target)
    if a.verdict not in VERDICTS:
        print(f'[!] verdict 只能是 {VERDICTS}', file=sys.stderr); sys.exit(2)
    st['tested'].append({
        'what': a.what, 'result': a.result, 'verdict': a.verdict,
        'at': now_iso(),
    })
    save(a.target, st)
    print(f'✅ 已记录：{a.verdict} · {a.what}')


def cmd_budget(a):
    st = require(a.target)
    if a.used is not None:
        st['budget']['used'] = int(a.used)
    if a.limit is not None:
        st['budget']['limit'] = int(a.limit)
    save(a.target, st)
    print(f'✅ 预算：{st["budget"]["used"]}/{st["budget"]["limit"]}')


def cmd_close(a):
    st = require(a.target)
    st['rounds'].append({
        'closed_at': now_iso(),
        'stage': st.get('stage', ''),
        'next_action': st.get('next_action', ''),
        'budget_used': st.get('budget', {}).get('used', 0),
        'blocked_by': list(st.get('blocked_by', [])),
        'open_hypotheses': [h['id'] for h in st.get('hypotheses', []) if h.get('state') == '未决'],
    })
    save(a.target, st)
    print(f'✅ 本轮收口已记录（第 {len(st["rounds"])} 轮）')


def cmd_why(a):
    """记录 / 打印「这一轮为什么这么打」——事件溯源的最小实现。"""
    st = load(a.target)
    if st is None:
        # 没有状态文件时自动建一个，避免"必须先 init"这个隐形前置条件
        st = new_state(a.target)
        print(f'（自动初始化状态文件：{path_of(a.target)}）')
    if a.trigger or a.action or a.stop or a.result:
        rec = {
            'round': len(st.get('why_log', [])) + 1,
            'at': now_iso(),
            'trigger': a.trigger or '',      # 为什么打这个目标/这条假设
            'action': a.action or '',        # 具体做了什么
            'stop': a.stop or '',            # 为什么停
            'result': a.result or '',        # 结论
            'hypotheses': [h['id'] for h in st.get('hypotheses', [])],
        }
        st.setdefault('why_log', []).append(rec)
        save(a.target, st)
        print(f'✅ 第 {rec["round"]} 轮「为什么」已记录')
        return
    log = st.get('why_log') or []
    if not log:
        print('（还没有 why 记录。用 --trigger/--action/--stop/--result 记一条）')
        return
    for r in log:
        print('-' * 60)
        print(f'第 {r.get("round")} 轮   {r.get("at","")}')
        if r.get('trigger'):
            print(f'  为什么打： {r["trigger"]}')
        if r.get('action'):
            print(f'  做了什么： {r["action"]}')
        if r.get('stop'):
            print(f'  为什么停： {r["stop"]}')
        if r.get('result'):
            print(f'  结论：     {r["result"]}')
        if r.get('hypotheses'):
            print(f'  当时假设： {", ".join(r["hypotheses"])}')


def fmt(st):
    L = []
    L.append('=' * 62)
    L.append(f'靶标   {st["target"]}')
    if st.get('domain'):
        L.append(f'主域   {st["domain"]}')
    L.append(f'阶段   {st.get("stage","")}    预算 {st.get("budget",{}).get("used",0)}/{st.get("budget",{}).get("limit",0)}')
    L.append(f'更新   {st.get("updated_at","")}  (rev {st.get("revision",0)})')
    L.append('=' * 62)
    L.append('')
    L.append('【下一步】')
    L.append('  ' + (st.get('next_action') or '（未填写）'))
    if st.get('blocked_by'):
        L.append('')
        L.append('【卡点】')
        for b in st['blocked_by']:
            L.append('  ⛔ ' + b)
    hs = st.get('hypotheses') or []
    if hs:
        L.append('')
        L.append('【假设清单】')
        for h in hs:
            L.append(f'  [{h.get("id")}] {h.get("state","?")}  {h.get("fingerprint","")}')
            if h.get('cves'):
                L.append(f'        CVE: {", ".join(h["cves"])}')
            if h.get('verify_method'):
                L.append(f'        验法: {h["verify_method"]}')
            if h.get('fail_signal'):
                L.append(f'        失败信号: {h["fail_signal"]}')
            if h.get('reason'):
                L.append(f'        说明: {h["reason"]}')
        open_n = [h['id'] for h in hs if h.get('state') == '未决']
        L.append(f'  → 未决 {len(open_n)} 条' + (f'：{", ".join(open_n)}' if open_n else '（全部归零 ✅）'))
    ts = st.get('tested') or []
    if ts:
        L.append('')
        L.append('【已试过】')
        for t in ts[-15:]:
            L.append(f'  {t.get("verdict","")}  {t.get("what","")} → {t.get("result","")}')
        if len(ts) > 15:
            L.append(f'  …（共 {len(ts)} 条，仅显示最近 15 条）')
    if st.get('notes'):
        L.append('')
        L.append('【备注】')
        L.append('  ' + st['notes'].replace('\n', '\n  '))
    wl = st.get('why_log') or []
    if wl:
        L.append('')
        L.append('【为什么这么打（历史）】')
        for r in wl[-5:]:
            L.append(f'  第 {r.get("round")} 轮 @ {r.get("at","")}')
            if r.get('trigger'):
                L.append(f'    为什么打： {r["trigger"]}')
            if r.get('action'):
                L.append(f'    做了什么： {r["action"]}')
            if r.get('stop'):
                L.append(f'    为什么停： {r["stop"]}')
            if r.get('result'):
                L.append(f'    结论：     {r["result"]}')
        if len(wl) > 5:
            L.append(f'    …（共 {len(wl)} 轮，仅显示最近 5 轮；完整见 state.py why）')
    if st.get('rounds'):
        L.append('')
        L.append(f'【历史收口】共 {len(st["rounds"])} 轮（最近一轮：{st["rounds"][-1].get("closed_at","")}）')
    L.append('')
    return '\n'.join(L)


def cmd_show(a):
    st = require(a.target)
    print(fmt(st))


def cmd_list(a):
    if not os.path.isdir(STATE_DIR):
        print('（还没有任何状态文件）'); return
    rows = []
    for fn in sorted(os.listdir(STATE_DIR)):
        if not fn.endswith('.json'):
            continue
        try:
            with open(os.path.join(STATE_DIR, fn), 'r', encoding='utf-8') as f:
                st = json.load(f)
        except Exception:
            continue
        open_n = len([h for h in st.get('hypotheses', []) if h.get('state') == '未决'])
        rows.append((st.get('updated_at', ''), st.get('target', fn), st.get('stage', ''),
                     st.get('budget', {}).get('used', 0), len(st.get('tested', [])), open_n,
                     (st.get('next_action') or '')[:40]))
    if not rows:
        print('（还没有任何状态文件）'); return
    rows.sort(reverse=True)
    print(f'{"靶标":28} {"阶段":8} {"请求":>5} {"已试":>4} {"未决":>4}  下一步')
    print('-' * 100)
    for _, t, stage, used, ntest, nopen, nxt in rows:
        print(f'{t[:26]:28} {stage[:8]:8} {used:5} {ntest:4} {nopen:4}  {nxt}')


def main():
    ap = argparse.ArgumentParser(description='靶标工作状态持久化')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('init'); p.add_argument('target'); p.add_argument('--domain', default=''); p.add_argument('--force', action='store_true'); p.set_defaults(f=cmd_init)
    p = sub.add_parser('set'); p.add_argument('target'); p.add_argument('--stage'); p.add_argument('--next'); p.add_argument('--domain'); p.add_argument('--notes'); p.add_argument('--add-blocked', nargs='+'); p.add_argument('--clear-blocked', action='store_true'); p.set_defaults(f=cmd_set)
    p = sub.add_parser('hypo'); p.add_argument('target'); p.add_argument('--id'); p.add_argument('--fingerprint'); p.add_argument('--cves'); p.add_argument('--verify'); p.add_argument('--fail'); p.add_argument('--state'); p.add_argument('--reason'); p.set_defaults(f=cmd_hypo)
    p = sub.add_parser('tested'); p.add_argument('target'); p.add_argument('--what', required=True); p.add_argument('--result', required=True); p.add_argument('--verdict', required=True); p.set_defaults(f=cmd_tested)
    p = sub.add_parser('budget'); p.add_argument('target'); p.add_argument('--used', type=int); p.add_argument('--limit', type=int); p.set_defaults(f=cmd_budget)
    p = sub.add_parser('close'); p.add_argument('target'); p.set_defaults(f=cmd_close)
    p = sub.add_parser('why'); p.add_argument('target'); p.add_argument('--trigger'); p.add_argument('--action'); p.add_argument('--stop'); p.add_argument('--result'); p.set_defaults(f=cmd_why)
    p = sub.add_parser('show'); p.add_argument('target'); p.set_defaults(f=cmd_show)
    p = sub.add_parser('list'); p.set_defaults(f=cmd_list)

    a = ap.parse_args()
    a.f(a)


if __name__ == '__main__':
    main()
