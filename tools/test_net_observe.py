#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""net_observe v2 测试：G-11 / G-12 / G-13 / G-14

设计原则：能不起真 tcpdump 的就不起（太重），但**每条都必须能真的失败**。
G-11 的核心是"不误杀别人"，这一条必须用真进程验证。
"""
import json
import os
import subprocess
import sys
import time

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, 'runs', 'tools'))
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

NO = os.path.join(WS, 'runs', 'tools', 'net_observe.py')
JUDGE = os.path.join(WS, 'runs', 'tools', 'judge_scope.mjs')
NODE = open(os.path.join(WS, 'runs', 'tools', 'node_path.txt'), encoding='utf-8').read().strip() \
    if os.path.exists(os.path.join(WS, 'runs', 'tools', 'node_path.txt')) else 'node'
SESSION = os.path.join(WS, 'runs', 'netobserve', 'session.json')

passed = failed = 0


def check(label, fn):
    global passed, failed
    try:
        fn()
        print('  ✅', label)
        passed += 1
    except Exception as e:
        print('  ❌', label, '→', type(e).__name__ + ':', e)
        failed += 1


def sh(cmd, timeout=180):
    script = 'source "%s"; kali %s' % (
        os.path.join(WS, 'runs', 'tools', 'kali_helper.sh').replace('\\', '/'),
        "'" + cmd.replace("'", "'\\''") + "'")
    r = subprocess.run(['bash', '-lc', script], capture_output=True, timeout=timeout)
    return (r.stdout or b'').decode('utf-8', 'replace')


def run(*args, timeout=240):
    r = subprocess.run([sys.executable, NO] + list(args), cwd=WS,
                       capture_output=True, timeout=timeout,
                       env=dict(os.environ, PYTHONIOENCODING='utf-8'))
    return (r.stdout or b'').decode('utf-8', 'replace'), (r.stderr or b'').decode('utf-8', 'replace')


print('=== G-14 判定引擎与主护栏一致 ===')


def t_judge_semantics():
    payload = json.dumps({
        'workspace': WS,
        'domains': ['www.<客户域名>', 'api.github.com', 'evil-not-scoped.example'],
        'ips': ['<IP>', '<IP>', '10.0.0.5', '999.1.1.1'],
    })
    r = subprocess.run([NODE, JUDGE], input=payload.encode('utf-8'),
                       capture_output=True, timeout=120)
    out = json.loads((r.stdout or b'').decode('utf-8'))
    assert out.get('ok') is True, 'judge 返回失败: %s' % out
    d = out['domains']
    i = out['ips']
    assert d['www.<客户域名>'] == 'target', 'ahnu 应为 target，实际 %s' % d['www.<客户域名>']
    assert d['api.github.com'] == 'service', 'github 应为 service'
    assert d['evil-not-scoped.example'] == 'out', '域外应 out，实际 %s' % d['evil-not-scoped.example']
    assert i['<IP>'] == 'target', '<IP> 应 target（CIDR 命中）'
    assert i['<IP>'] == 'out', '<IP> 应 out'
    assert i['10.0.0.5'] == 'local', '内网应 local'
    assert i['999.1.1.1'] == 'invalid', '非法 IP 应 invalid'


check('judge_scope：语义与主引擎一致（含 CIDR / service / 内网 / 非法）', t_judge_semantics)


def t_judge_auth_expired():
    scope_p = os.path.join(WS, 'runs', 'tools', 'scope.json')
    bak = scope_p + '.testbak'
    import shutil
    shutil.copy2(scope_p, bak)
    try:
        d = json.load(open(scope_p, encoding='utf-8'))
        d.setdefault('authorization', {})['expiresAt'] = '2020-01-01T00:00:00Z'
        json.dump(d, open(scope_p, 'w', encoding='utf-8'), ensure_ascii=False)
        payload = json.dumps({'workspace': WS, 'domains': ['www.<客户域名>'], 'ips': []})
        r = subprocess.run([NODE, JUDGE], input=payload.encode('utf-8'),
                           capture_output=True, timeout=120)
        out = json.loads((r.stdout or b'').decode('utf-8'))
        assert out.get('ok') is False, '授权过期时 ok 必须为 false'
        assert '过期' in str(out.get('reason')) or 'expiresAt' in str(out.get('reason')), \
            '理由应说明过期，实际: %s' % out.get('reason')
    finally:
        shutil.move(bak, scope_p)


check('judge_scope：授权过期 → ok=false（不能当成"没越界"）', t_judge_auth_expired)


print('\n=== G-13 抓包状态与能力边界 ===')


def t_limits():
    out, _ = run('report')
    assert '未覆盖的网络行为' in out, '报告必须列出未覆盖的网络行为'
    for kw in ['DoH', 'QUIC', 'ICMP', '未解密']:
        assert kw in out, '未覆盖清单缺 %s' % kw


check('报告列出未覆盖的网络行为（DoH/QUIC/ICMP/未解密）', t_limits)


def t_partial_marks():
    # 造一个 session：两个 pid 都是死的 -> stop 时 captureStatus 应为 COMPLETE 或 PARTIAL
    os.makedirs(os.path.dirname(SESSION), exist_ok=True)
    json.dump({
        'sessionId': 'test-partial',
        'state': 'running',
        'startedAt': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'procs': {
            'dns': {'pid': 999998, 'cmdline': '', 'expect': 'tcpdump -i any udp port 53'},
            'syn': {'pid': 999999, 'cmdline': '', 'expect': 'tcpdump -i any tcp-syn'},
        },
        'logs': {'dns': '/tmp/nonexistent_dns.log', 'syn': '/tmp/nonexistent_syn.log'},
    }, open(SESSION, 'w', encoding='utf-8'), ensure_ascii=False)
    out, _ = run('stop')
    assert '抓包状态' in out, 'stop 应输出抓包状态'
    assert ('失败' in out) or ('部分' in out) or ('未知' in out), \
        '进程都不存在且没数据时应标为不完整，实际输出:\n' + out[:400]
    assert '不等于' in out or '不完整' in out, '不完整时必须提示"没发现越界不等于没有越界"'


check('进程缺失 + 无数据 → 状态为不完整且给出告警', t_partial_marks)


print('\n=== G-12 status 只看本 session 的 pid ===')


def t_status_own_pid():
    # 造一个假 session，pid 指向一个确定不存在的号
    json.dump({
        'sessionId': 'test-status',
        'state': 'running',
        'startedAt': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'procs': {
            'dns': {'pid': 999997, 'cmdline': '', 'expect': 'udp port 53'},
            'syn': {'pid': 999996, 'cmdline': '', 'expect': 'tcp-syn'},
        },
        'logs': {'dns': '/tmp/x.log', 'syn': '/tmp/y.log'},
    }, open(SESSION, 'w', encoding='utf-8'), ensure_ascii=False)
    out, _ = run('status')
    assert 'test-status' in out, 'status 应显示 sessionId'
    assert 'alive=False' in out, '死进程应显示 alive=False，实际:\n' + out[:400]
    assert '不完整' in out or 'PARTIAL' in out or 'stop' in out, '应提示会话不健康'


check('status 用 session 记录的 pid（不是全局 pgrep）', t_status_own_pid)


print('\n=== G-11 不误杀别人的 tcpdump（真进程验证）===')


def t_dont_kill_others():
    # 前面的用例可能留下假 session，先清掉
    if os.path.exists(SESSION):
        os.remove(SESSION)
    # 起一个"别人的" tcpdump
    sh('pkill -f "udp port 19999" 2>/dev/null; sleep 1; '
       'setsid sh -c "tcpdump -i any -n -l \\"udp port 19999\\" > /tmp/other_obs_test.log 2>/dev/null" '
       '< /dev/null > /dev/null 2>&1 & sleep 2')
    other = sh('pgrep -f "udp port 19999" | head -1').strip().splitlines()
    other_pid = other[-1].strip() if other else ''
    assert other_pid.isdigit(), '没能起"别人的" tcpdump（可能缺 CAP_NET_RAW）'
    try:
        # 我们的 start
        out, err = run('start')
        assert '已开始观测' in out, 'start 失败: %s %s' % (out[:300], err[:300])
        sess = json.load(open(SESSION, encoding='utf-8'))
        my = [sess['procs']['dns']['pid'], sess['procs']['syn']['pid']]
        # 我们的 stop
        out2, _ = run('stop')
        assert '已终止' in out2, 'stop 应报告终止了自己的进程'
        # 关键断言：别人的还活着
        alive = sh('if [ -d /proc/%s ]; then echo ALIVE; else echo DEAD; fi' % other_pid).strip()
        assert 'ALIVE' in alive, '别人的 tcpdump 被误杀了！（pid=%s）' % other_pid
        # 而且我们的确实死了
        for pid in my:
            st = sh('if [ -d /proc/%d ]; then echo ALIVE; else echo DEAD; fi' % pid).strip()
            assert 'DEAD' in st, '自己的 pid=%d 没被停掉' % pid
    finally:
        sh('pkill -f "udp port 19999" 2>/dev/null; true')


check('同时有别人的 tcpdump 时，stop 只杀自己的', t_dont_kill_others)


print('\n=== 清理 ===')
sh('pkill -f "tcpdump -i any" 2>/dev/null; true')
print('  已清理 Kali 上的 tcpdump')
if os.path.exists(SESSION):
    os.remove(SESSION)

print('\n结果: %d 通过 / %d 失败' % (passed, failed))
sys.exit(0 if failed == 0 else 1)
