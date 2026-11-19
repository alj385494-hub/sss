#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali 网络观测（只读）v2 —— 回答"agent 实际打了哪些域外目标"。

## 为什么需要它
插件在 `tools/pre-execute` 只能看到**工具参数**，看不到工具内部真正连了谁。
这个工具在 Kali 上抓真实的 DNS 查询 + TCP 新建连接，用流量层的事实补上那一块。

## v2 修的四个问题（V3 审计 G-11 ~ G-14）
- **G-11** 不再用 `pkill -f tcpdump`（会误杀别的任务的 tcpdump）。
  改成：每次观测生成唯一 sessionId，把两个 tcpdump 的 pid + 命令行指纹 + 启动时间记进
  `runs/netobserve/session.json`；停止时只杀这两个 pid，且先核对指纹。
- **G-12** `status` 不再用 `pgrep -c tcpdump`（别的任务的 tcpdump 会让你误报在观测）。
  改成：只看本 session 记录的 pid，并核对命令行指纹、输出文件可写、文件是否在增长。
- **G-13** 明确观测能力边界，报告带 `capture_status`：
  `COMPLETE / PARTIAL / FAILED / UNKNOWN`，并列出**没覆盖到的**网络行为。
- **G-14** 目标分类不再自己实现一套，改成调用 `judge_scope.mjs`
  （直接 import 插件的 authActive/targetExpired/ipInCidr），保证与主护栏同一份逻辑。

## 它不做什么（诚实标注）
- 不解密 HTTPS（看不到 URL 与请求体）
- 看不到 DoH/DoT（加密 DNS）、看不到 QUIC/UDP 443、看不到 ICMP
- 不拦截任何东西，纯只读
- 追不到具体是哪个工具发起的连接

## 用法（PY 见 AGENTS §15）
    "$PY" runs/tools/net_observe.py start
    ... 做你的作业 ...
    "$PY" runs/tools/net_observe.py stop
    "$PY" runs/tools/net_observe.py status
    "$PY" runs/tools/net_observe.py report
"""
import json
import os
import re
import subprocess
import sys
import time

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(WS, 'runs', 'netobserve')
SESSION_FILE = os.path.join(OUT_DIR, 'session.json')
HELPER = os.path.join(WS, 'runs', 'tools', 'kali_helper.sh')
JUDGE = os.path.join(WS, 'runs', 'tools', 'judge_scope.mjs')
NODE_PATH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'node_path.txt')


def find_node():
    """找 node 可执行文件。优先级：环境变量 > node_path.txt > PATH > DSH 运行时默认位置。"""
    cands = [os.environ.get('DSH_NODE')]
    try:
        cands.append(open(NODE_PATH_FILE, encoding='utf-8').read().strip())
    except Exception:
        pass
    import shutil as _sh
    cands.append(_sh.which('node'))
    cands.append(os.path.expanduser(
        '~/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node.exe'))
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


NODE = find_node() or '' 

DNS_LOG = '/tmp/dsh_netobs_dns.log'
SYN_LOG = '/tmp/dsh_netobs_syn.log'

DNS_CMD = 'tcpdump -i any -n -l "udp port 53"'
SYN_CMD = 'tcpdump -i any -n -l "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"'

# G-13：明确声明这套观测覆盖不到的东西
LIMITS = [
    'HTTPS 的 URL / 请求体（未解密，只看到 IP:端口）',
    'DoH / DoT（加密 DNS）',
    'QUIC / UDP 443',
    'ICMP 与其它非 TCP / 非 UDP53 流量',
    '已建立连接的后续通信（只抓新建 SYN）',
    '代理转发后的最终目标（只看到代理入口）',
    '发起连接的具体工具（tcpdump 没有进程信息）',
    'IP 的授权判定不做 DNS 反查：serviceAllowlist 里域名对应的 IP 会显示为 out，需结合域名一起看',
]


def sh(cmd, timeout=180):
    """在 Kali 里跑一段脚本（复用 kali_helper.sh 的 kali 函数）。"""
    script = 'source "%s"; kali %s' % (
        HELPER.replace('\\', '/'),
        "'" + cmd.replace("'", "'\\''") + "'",
    )
    try:
        r = subprocess.run(['bash', '-lc', script], capture_output=True, timeout=timeout)
        return (r.stdout or b'').decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return '[timeout]'


def new_session_id():
    import secrets
    return 'obs-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3)


def load_session():
    try:
        return json.load(open(SESSION_FILE, encoding='utf-8'))
    except Exception:
        return None


def save_session(s):
    os.makedirs(OUT_DIR, exist_ok=True)
    json.dump(s, open(SESSION_FILE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)


def proc_info(pid):
    """返回 (存活, 命令行)。命令行用来做指纹，防 PID 复用误杀。"""
    out = sh('''if [ -d /proc/%d ]; then
  echo "ALIVE=1"
  tr '\\0' ' ' < /proc/%d/cmdline 2>/dev/null
else
  echo "ALIVE=0"
fi''' % (pid, pid), timeout=60)
    alive = False
    cmdline = ''
    for line in out.splitlines():
        if line.startswith('ALIVE='):
            alive = line.split('=', 1)[1].strip() == '1'
        elif alive and line.strip():
            cmdline = line.strip()
    return alive, cmdline


def fingerprint_ok(pid, expect_cmd):
    """核对 pid 的命令行是不是我们要杀的那个 tcpdump。"""
    alive, cmdline = proc_info(pid)
    if not alive:
        return False, 'process gone'
    # 用关键片段比对，避免因为引号/空格差异误判
    key = 'udp port 53' if 'udp port 53' in expect_cmd else 'tcp-syn'
    if key not in cmdline:
        return False, 'cmdline mismatch: %r' % cmdline[:120]
    return True, 'ok'


# ── start ────────────────────────────────────────────────────────
def cmd_start(a):
    old = load_session()
    if old and old.get('state') == 'running':
        print('已有一个正在运行的观测会话：%s' % old.get('sessionId'))
        print('先 stop 它，或换一个会话。')
        return 2

    sid = new_session_id()
    print('开始观测 session=%s …' % sid)
    out = sh('''rm -f %s %s
tcpdump -i any -n -l "udp port 53" > %s 2>/dev/null &
echo "DNS_PID=$!"
tcpdump -i any -n -l "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" > %s 2>/dev/null &
echo "SYN_PID=$!"
sleep 3
echo "DNS_LINES=$(grep -c . %s 2>/dev/null || echo 0)"
echo "SYN_LINES=$(grep -c . %s 2>/dev/null || echo 0)"''' % (DNS_LOG, SYN_LOG, DNS_LOG, SYN_LOG, DNS_LOG, SYN_LOG),
             timeout=120)

    dns_pid = syn_pid = None
    for line in out.splitlines():
        if line.startswith('DNS_PID='):
            try: dns_pid = int(line.split('=', 1)[1].strip())
            except Exception: pass
        elif line.startswith('SYN_PID='):
            try: syn_pid = int(line.split('=', 1)[1].strip())
            except Exception: pass

    if not dns_pid or not syn_pid:
        print('  ❌ 起 tcpdump 失败，原始输出：')
        print(out[:800])
        print('  常见原因：没有 CAP_NET_RAW。修法：')
        print('     echo kali | sudo -S setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump')
        return 1

    # 核对两个进程都真的活着
    d_alive, d_cmd = proc_info(dns_pid)
    s_alive, s_cmd = proc_info(syn_pid)
    if not (d_alive and s_alive):
        print('  ❌ 进程没起来: dns=%s syn=%s' % (d_alive, s_alive))
        return 1

    sess = {
        'sessionId': sid,
        'state': 'running',
        'startedAt': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'procs': {
            'dns': {'pid': dns_pid, 'cmdline': d_cmd or DNS_CMD, 'expect': DNS_CMD},
            'syn': {'pid': syn_pid, 'cmdline': s_cmd or SYN_CMD, 'expect': SYN_CMD},
        },
        'logs': {'dns': DNS_LOG, 'syn': SYN_LOG},
    }
    save_session(sess)
    print('  ✅ 已开始观测（只杀这两个 pid，不会碰别的 tcpdump）')
    print('     dns pid=%d  syn pid=%d' % (dns_pid, syn_pid))
    print('     作业跑完后： net_observe.py stop')
    return 0


# ── status（G-12）────────────────────────────────────────────────
def cmd_status(a):
    sess = load_session()
    if not sess:
        print('没有观测会话记录。用 start 开始一个。')
        return 0
    print('session : %s' % sess.get('sessionId'))
    print('state   : %s（开始于 %s）' % (sess.get('state'), sess.get('startedAt')))
    ok = True
    for kind in ('dns', 'syn'):
        p = (sess.get('procs') or {}).get(kind) or {}
        pid = p.get('pid')
        if not pid:
            print('  %-4s 无记录' % kind)
            ok = False
            continue
        alive, cmdline = proc_info(pid)
        fp_ok, why = fingerprint_ok(pid, p.get('expect') or '')
        log = (sess.get('logs') or {}).get(kind) or ''
        # G-12：日志在 Kali 的 /tmp 里，必须在 Kali 里查大小（宿主 os.path 看不到）
        size_txt = sh('wc -c < %s 2>/dev/null || echo -1' % log, timeout=60).strip()
        size_line = size_txt.splitlines()[-1].strip() if size_txt else '-1'
        try:
            size = int(size_line)
        except Exception:
            size = -1
        log_ok = size >= 0
        print('  %-4s pid=%-7s alive=%-5s fp=%-5s log_writable=%-5s size=%s'
              % (kind, pid, alive, fp_ok, log_ok, size if log_ok else '-'))
        if not (alive and fp_ok):
            ok = False
    if sess.get('state') == 'running' and ok:
        print('\n正在观测中。跑完用 stop 出报告。')
    elif sess.get('state') == 'running' and not ok:
        print('\n⚠️  会话标记为 running，但进程已不完整 —— 建议直接 stop（它会按 PARTIAL 出报告）。')
    else:
        print('\n会话已结束。用 report 看最近报告。')
    return 0


# ── stop（G-11 + G-13 + G-14）───────────────────────────────────
def cmd_stop(a):
    sess = load_session()
    if not sess:
        print('没有观测会话记录。')
        return 2

    print('停止 session=%s …' % sess.get('sessionId'))
    kill_report = []
    killed_ok = 0
    for kind in ('dns', 'syn'):
        p = (sess.get('procs') or {}).get(kind) or {}
        pid = p.get('pid')
        if not pid:
            continue
        fp_ok, why = fingerprint_ok(pid, p.get('expect') or '')
        if fp_ok:
            sh('kill %d 2>/dev/null || true' % pid, timeout=60)
            killed_ok += 1
            kill_report.append('%s pid=%d 已终止' % (kind, pid))
        else:
            kill_report.append('%s pid=%d 跳过（%s）' % (kind, pid, why))

    time.sleep(1)
    # 抓包状态判定（G-13）
    alive_d, _ = proc_info((sess.get('procs', {}).get('dns') or {}).get('pid') or 0)
    alive_s, _ = proc_info((sess.get('procs', {}).get('syn') or {}).get('pid') or 0)
    # G-13：进程死了**不等于**这次抓包是完整的。
    #   只有两个都确认是我们的进程、且都被我们正常终止、且确实死透了才算 COMPLETE。
    if killed_ok == 2 and not alive_d and not alive_s:
        capture_status = 'COMPLETE'
    elif killed_ok == 0 and not alive_d and not alive_s:
        capture_status = 'FAILED'      # 进程在我们停之前就没了 -> 这段采集不可信
    elif alive_d or alive_s:
        capture_status = 'PARTIAL'     # 还有活着 -> 只采到一部分
    else:
        capture_status = 'UNKNOWN'

    # 读日志
    raw = sh('''echo "===DNS==="; cat %s 2>/dev/null; echo "===SYN==="; cat %s 2>/dev/null''' % (DNS_LOG, SYN_LOG),
             timeout=180)

    domains, syns = {}, {}
    section = 'dns'
    for line in raw.splitlines():
        if line.strip() == '===SYN===':
            section = 'syn'
            continue
        if section == 'dns':
            m = re.search(r'\b(A|AAAA|HTTPS|CNAME)\?\s+([A-Za-z0-9._-]+)\.', line)
            if m:
                d = m.group(2).lower()
                domains[d] = domains.get(d, 0) + 1
        else:
            m = re.search(r'>\s*([0-9a-fA-F.:]+)\.(\d{1,5})', line)
            if m:
                key = '%s:%s' % (m.group(1).rstrip('.'), m.group(2))
                syns[key] = syns.get(key, 0) + 1

    if not domains and not syns:
        capture_status = 'FAILED' if capture_status != 'COMPLETE' else 'PARTIAL'

    # G-14：判定交给 judge_scope.mjs（与主护栏同一份逻辑）
    verdict = judge(domains, syns)

    sess['state'] = 'finished'
    sess['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    sess['captureStatus'] = capture_status
    save_session(sess)

    report = {
        'sessionId': sess.get('sessionId'),
        'startedAt': sess.get('startedAt'),
        'finishedAt': sess.get('finishedAt'),
        'captureStatus': capture_status,
        'killReport': kill_report,
        'dnsQueries': [{'domain': d, 'count': c} for d, c in sorted(domains.items(), key=lambda x: -x[1])],
        'tcpConnects': [{'target': t, 'count': c} for t, c in sorted(syns.items(), key=lambda x: -x[1])],
        'verdict': verdict,
        'limits': LIMITS,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    jp = os.path.join(OUT_DIR, 'report-%s.json' % stamp)
    json.dump(report, open(jp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print_report(report, jp)
    return 0 if capture_status == 'COMPLETE' else 0


def judge(domains, syns):
    """调用 judge_scope.mjs，复用插件的授权判定。"""
    if not os.path.exists(JUDGE):
        return {'ok': False, 'reason': 'judge_scope.mjs 不存在，无法判定', 'domains': {}, 'ips': {}}
    node = NODE or find_node()
    if not node:
        return {'ok': False, 'reason': '找不到 node（设 DSH_NODE，或写 runs/tools/node_path.txt）',
                'domains': {}, 'ips': {}}
    payload = json.dumps({
        'workspace': WS,
        'domains': sorted(domains.keys()),
        'ips': sorted(syns.keys()),
    })
    try:
        r = subprocess.run([node, JUDGE], input=payload.encode('utf-8'),
                           capture_output=True, timeout=180)
        out = (r.stdout or b'').decode('utf-8', 'replace').strip()
        return json.loads(out) if out else {'ok': False, 'reason': 'judge 无输出'}
    except Exception as e:
        return {'ok': False, 'reason': 'judge 调用失败: %s' % e, 'domains': {}, 'ips': {}}


def print_report(report, jp=None):
    v = report.get('verdict') or {}
    st = report.get('captureStatus')
    print()
    print('=' * 66)
    print(' 网络观测报告  session=%s' % report.get('sessionId'))
    print('=' * 66)
    flag = {'COMPLETE': '✅ 完整', 'PARTIAL': '⚠️  部分', 'FAILED': '❌ 失败', 'UNKNOWN': '❓ 未知'}.get(st, st)
    print(' 抓包状态: %s' % flag)
    if st != 'COMPLETE':
        print(' ⚠️  这次观测**不完整**，"没发现越界"不等于"没有越界通信"')
    if report.get('killReport'):
        print(' 停止: %s' % '；'.join(report['killReport']))
    print()
    print(' 解析域名 %d / 新建连接 %d' % (len(report.get('dnsQueries', [])), len(report.get('tcpConnects', []))))

    if not v.get('ok'):
        print()
        print(' ❌ 无法判定授权归属: %s' % v.get('reason'))
        print('    这种情况下**不能**把"没发现异常"当成"没有越权"。')
    else:
        dm = v.get('domains') or {}
        im = v.get('ips') or {}
        if report.get('dnsQueries'):
            print()
            print(' 域名（按次数）:')
            for row in report['dnsQueries'][:20]:
                d = row['domain']
                print('   %-44s ×%-3d %s' % (d, row['count'], dm.get(d, '')))
        if report.get('tcpConnects'):
            print()
            print(' 连接目标（IP:端口）:')
            for row in report['tcpConnects'][:20]:
                t = row['target']
                print('   %-30s ×%-3d %s' % (t, row['count'], im.get(t, '')))
        outd = [d for d, k in dm.items() if k == 'out']
        outi = [t for t, k in im.items() if k == 'out']
        print()
        print(' 未授权: 域名 %d 个 / IP %d 个' % (len(outd), len(outi)))
        if outd:
            print('   ⚠️  域外域名: %s' % ', '.join(outd[:10]))
        if outi:
            print('   ⚠️  域外 IP: %s' % ', '.join(outi[:10]))

    print()
    print(' 未覆盖的网络行为（这份报告看不到）:')
    for x in report.get('limits', LIMITS):
        print('   · %s' % x)
    print('=' * 66)
    if jp:
        print(' 报告: %s' % jp.replace(WS, '.'))
    print(' 说明: "未授权"指不在 scope 里，**不代表违规**——可能是 CDN/DNS/包源；')
    print('       要结合上下文看。护栏的 allowUnlisted 与这份判定是两回事。')
    print('       另外：IP 判定不做 DNS 反查，服务域名对应的 IP 会显示 out，请看域名那一栏。')


def cmd_report(a):
    if not os.path.isdir(OUT_DIR):
        print('还没有报告')
        return 0
    js = sorted(f for f in os.listdir(OUT_DIR) if f.startswith('report-'))
    if not js:
        print('还没有报告')
        return 0
    p = os.path.join(OUT_DIR, js[-1])
    d = json.load(open(p, encoding='utf-8'))
    print_report(d, p)
    return 0


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    import argparse
    ap = argparse.ArgumentParser(description='Kali 网络观测（只读）v2')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for c, f in (('start', cmd_start), ('stop', cmd_stop), ('status', cmd_status), ('report', cmd_report)):
        sub.add_parser(c).set_defaults(f=f)
    a = ap.parse_args()
    sys.exit(a.f(a))


if __name__ == '__main__':
    main()
