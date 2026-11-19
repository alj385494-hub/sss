#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali 网络观测（只读版）—— 回答"agent 实际打了哪些域外目标"。

为什么需要它：
    插件在 `tools/pre-execute` 只能看到**工具参数**，看不到工具内部真正连了谁。
    这个工具在 Kali 上抓真实的 DNS 查询 + TCP 新建连接，用流量层的事实补上那一块。

它做什么：
    start  在 Kali 后台起 tcpdump（DNS + TCP SYN），记 pid
    stop   停抓包，解析日志，与 runs/tools/scope.json 比对，输出越界清单
    status 看抓包是否在跑
    report 看最近一次报告

它不做什么（诚实标注）：
    · 不解密 HTTPS（看不到 URL 路径与请求体）
    · 看不到 DoH/DoT（加密 DNS）；Kali 的明文 DNS 走 VBox NAT 的 192.168.1.1
    · 不拦截任何东西，纯只读
    · 追不到具体是哪个工具发起的连接（tcpdump 没有进程信息）

用法（PY 见 AGENTS §15）：
    "$PY" runs/tools/net_observe.py start
    ... 做你的作业 ...
    "$PY" runs/tools/net_observe.py stop
"""
import json
import os
import re
import subprocess
import sys
import time

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(WS, 'runs', 'netobserve')
SCOPE = os.path.join(WS, 'runs', 'tools', 'scope.json')
HELPER = os.path.join(WS, 'runs', 'tools', 'kali_helper.sh')

DNS_LOG = '/tmp/dsh_netobs_dns.log'
SYN_LOG = '/tmp/dsh_netobs_syn.log'
PID_FILE = '/tmp/dsh_netobs.pid'


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


def cmd_start(a):
    print('在 Kali 起 tcpdump …')
    out = sh('''pkill -f "tcpdump -i any -n -l" 2>/dev/null; sleep 1
rm -f %s %s
tcpdump -i any -n -l "udp port 53" > %s 2>/dev/null &
echo $! > %s
tcpdump -i any -n -l "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" > %s 2>/dev/null &
sleep 3
echo "PROCS=$(pgrep -c tcpdump)"''' % (DNS_LOG, SYN_LOG, DNS_LOG, PID_FILE, SYN_LOG), timeout=120)
    for line in out.splitlines():
        if line.startswith('PROCS='):
            n = line.split('=', 1)[1].strip()
            print('  tcpdump 进程数: %s' % n)
            if n == '0':
                print('  ❌ 没起来。检查 tcpdump 是否有 CAP_NET_RAW：')
                print('     echo kali | sudo -S setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump')
                return 1
            os.makedirs(OUT_DIR, exist_ok=True)
            with open(os.path.join(OUT_DIR, 'session.json'), 'w', encoding='utf-8') as f:
                json.dump({'started_at': time.strftime('%Y-%m-%dT%H:%M:%S')}, f)
            print('  ✅ 已开始观测。作业跑完后执行： net_observe.py stop')
            return 0
    print(out[:500])
    return 1


def cmd_stop(a):
    print('停止抓包并分析 …')
    sh('''pkill -f "tcpdump -i any -n -l" 2>/dev/null
sleep 1
echo "DNS_LINES=$(grep -c . %s 2>/dev/null || echo 0)"
echo "SYN_LINES=$(grep -c . %s 2>/dev/null || echo 0)"
echo "===DNS_BEGIN==="; cat %s 2>/dev/null
echo "===DNS_END==="
echo "===SYN_BEGIN==="; cat %s 2>/dev/null
echo "===SYN_END==="''' % (DNS_LOG, SYN_LOG, DNS_LOG, SYN_LOG), timeout=180)

    raw = sh('''cat %s 2>/dev/null; echo "===SYN==="; cat %s 2>/dev/null''' % (DNS_LOG, SYN_LOG), timeout=120)

    # 解析 DNS：形如 `... A? example.com. (52)`
    domains = {}
    syns = {}
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
                ip = m.group(1).rstrip('.')
                port = m.group(2)
                key = '%s:%s' % (ip, port)
                syns[key] = syns.get(key, 0) + 1

    # 与 scope.json 比对
    scope_hits = classify(domains, syns)

    report = {
        'finished_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'dns_queries': [{'domain': d, 'count': c} for d, c in sorted(domains.items(), key=lambda x: -x[1])],
        'tcp_connects': [{'target': t, 'count': c} for t, c in sorted(syns.items(), key=lambda x: -x[1])],
        'verdict': scope_hits,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    jp = os.path.join(OUT_DIR, 'report-%s.json' % stamp)
    with open(jp, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=1)

    print()
    print('=' * 62)
    print(' 网络观测报告')
    print('=' * 62)
    print(' 解析域名 %d 个 / 新建连接 %d 个' % (len(domains), len(syns)))
    print()
    if domains:
        print(' 域名（按次数）:')
        for d, c in sorted(domains.items(), key=lambda x: -x[1])[:20]:
            mark = scope_hits['domain'].get(d)
            print('   %-42s ×%-3d %s' % (d, c, mark or ''))
    if syns:
        print()
        print(' 连接目标（IP:端口）:')
        for t, c in sorted(syns.items(), key=lambda x: -x[1])[:20]:
            mark = scope_hits['ip'].get(t)
            print('   %-30s ×%-3d %s' % (t, c, mark or ''))
    print()
    print(' 越界: 域名 %d 个 / IP %d 个' % (len(scope_hits['out_domains']), len(scope_hits['out_ips'])))
    if scope_hits['out_domains']:
        print('   ⚠️  域外域名: %s' % ', '.join(scope_hits['out_domains'][:10]))
    if scope_hits['out_ips']:
        print('   ⚠️  域外 IP: %s' % ', '.join(scope_hits['out_ips'][:10]))
    print('=' * 62)
    print(' 报告: %s' % jp.replace(WS, '.'))
    print(' 注意：这不代表违规——解析/连接基础设施(CDN/DNS/包源)是正常的；')
    print('       要看的是「域外 + 与被测目标无关」的那些。')
    return 0



def ip_in_cidr(ip, cidr):
    """IPv4 CIDR 匹配。非 IPv4 或格式不对一律返回 False。"""
    try:
        if '/' not in cidr:
            return ip == cidr
        base, bits = cidr.split('/')
        bits = int(bits)
        parts = [int(x) for x in ip.split('.')]
        bparts = [int(x) for x in base.split('.')]
        if len(parts) != 4 or len(bparts) != 4:
            return False
        to_int = lambda xs: (xs[0] << 24) | (xs[1] << 16) | (xs[2] << 8) | xs[3]
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (to_int(parts) & mask) == (to_int(bparts) & mask)
    except Exception:
        return False


def classify(domains, syns):
    """和 scope.json 比对。返回每个目标的判定标记与越界清单。"""
    scope = {}
    if os.path.exists(SCOPE):
        try:
            scope = json.load(open(SCOPE, encoding='utf-8'))
        except Exception:
            scope = {}

    allow_domains = []
    allow_ips = []
    tgt = scope.get('targets') or {}
    if isinstance(tgt, dict):
        if isinstance(tgt.get('domains'), list):
            allow_domains += [str(x).lower() for x in tgt['domains']]
        if isinstance(tgt.get('ips'), list):
            allow_ips += [str(x) for x in tgt['ips']]
        for name, t in tgt.items():
            if isinstance(t, dict):
                allow_domains += [str(x).lower() for x in (t.get('domains') or [])]
                allow_ips += [str(x) for x in (t.get('ips') or [])]
        # 兜底：旧结构可能被收在 $legacy 里，也要认
        legacy = tgt.get('$legacy') or {}
        if isinstance(legacy, dict):
            for t in legacy.values():
                if isinstance(t, dict):
                    allow_domains += [str(x).lower() for x in (t.get('domains') or [])]
                    allow_ips += [str(x) for x in (t.get('ips') or [])]
    service = [str(x).lower() for x in (scope.get('serviceAllowlist') or scope.get('excludeDomains') or [])]

    def dom_mark(d):
        if any(d == x or d.endswith('.' + x) for x in allow_domains):
            return '← 授权目标'
        if any(d == x or d.endswith('.' + x) for x in service):
            return '← 辅助服务'
        return None

    dm, im = {}, {}
    out_d, out_i = [], []
    for d in domains:
        m = dom_mark(d)
        if m:
            dm[d] = m
        else:
            out_d.append(d)

    for t in syns:
        ip = t.rsplit(':', 1)[0]
        if ip in allow_ips or any(ip_in_cidr(ip, c) for c in allow_ips if '/' in c):
            im[t] = '← 授权 IP'
        elif ip.startswith(('10.', '192.168.', '127.', '169.254.')) or any(
                ip.startswith('172.%d.' % n) for n in range(16, 32)):
            im[t] = '← 内网'
        else:
            out_i.append(t)

    return {'domain': dm, 'ip': im, 'out_domains': out_d, 'out_ips': out_i}


def cmd_status(a):
    out = sh('pgrep -c tcpdump 2>/dev/null || echo 0', timeout=60)
    n = out.strip().splitlines()[-1] if out.strip() else '0'
    print('Kali 上 tcpdump 进程数: %s' % n)
    if n == '0':
        print('  未在观测。运行 net_observe.py start 开始。')
    else:
        print('  正在观测。跑完用 net_observe.py stop 出报告。')
    return 0


def cmd_report(a):
    if not os.path.isdir(OUT_DIR):
        print('还没有报告')
        return 0
    js = sorted(f for f in os.listdir(OUT_DIR) if f.startswith('report-'))
    if not js:
        print('还没有报告')
        return 0
    p = os.path.join(OUT_DIR, js[-1])
    print('最近一次报告: %s' % p.replace(WS, '.'))
    d = json.load(open(p, encoding='utf-8'))
    print('  完成时间: %s' % d.get('finished_at'))
    print('  域名 %d / 连接 %d' % (len(d.get('dns_queries', [])), len(d.get('tcp_connects', []))))
    v = d.get('verdict', {})
    print('  越界: 域名 %d / IP %d' % (len(v.get('out_domains', [])), len(v.get('out_ips', []))))
    return 0


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    import argparse
    ap = argparse.ArgumentParser(description='Kali 网络观测（只读）')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for c, f in (('start', cmd_start), ('stop', cmd_stop), ('status', cmd_status), ('report', cmd_report)):
        sub.add_parser(c).set_defaults(f=f)
    a = ap.parse_args()
    sys.exit(a.f(a))


if __name__ == '__main__':
    main()
