# -*- coding: utf-8 -*-
"""state.py 第二轮优化测试：G-15 / G-16 / G-17 / G-22

每条都要能真的失败。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.getcwd(), 'runs', 'tools'))
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass
import state

SF = os.path.join(os.getcwd(), 'runs', 'tmp', '_state_v2_worker.py')
passed = 0
failed = 0


def check(label, fn):
    global passed, failed
    try:
        fn()
        print('  ✅', label)
        passed += 1
    except Exception as e:
        print('  ❌', label, '→', type(e).__name__ + ':', e)
        failed += 1


def clean(target):
    p = state.path_of(target)
    for f in (p, p + '.lock'):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    for f in os.listdir(state.STATE_DIR):
        if f.startswith(os.path.basename(p) + '.tmp'):
            try:
                os.remove(os.path.join(state.STATE_DIR, f))
            except Exception:
                pass
    return p


# ── 工作进程：改不同字段 ────────────────────────────────────────
WORKER = '''# -*- coding: utf-8 -*-
import sys, os, time
sys.path.insert(0, os.path.join(os.getcwd(), 'runs', 'tools'))
import state
tag = sys.argv[1]
field = sys.argv[2]
def _do(st):
    time.sleep(0.01)
    if field == 'tested':
        st.setdefault('tested', []).append({'what': tag, 'verdict': '排除'})
    elif field == 'hypo':
        st.setdefault('hypotheses', []).append({'id': tag, 'state': '未决'})
    elif field == 'why':
        st.setdefault('why_log', []).append({'tag': tag})
    elif field == 'notes':
        st.setdefault('notes', '') or st.__setitem__('notes', '')
        st['notes'] = (st.get('notes') or '') + '[' + tag + ']'
state.mutate(sys.argv[3], _do)
'''
open(SF, 'w', encoding='utf-8').write(WORKER)

print('=== G-15 并发：8 进程同时改不同字段 ===')
T1 = '__v2_concurrent__'
clean(T1)
state.save(T1, state.new_state(T1))

procs = []
for i in range(8):
    field = ['tested', 'hypo', 'why', 'notes'][i % 4]
    procs.append(subprocess.Popen([sys.executable, SF, 'w%d' % i, field, T1],
                                  cwd=os.getcwd(),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
errs = []
for i, pr in enumerate(procs):
    out, err = pr.communicate(timeout=90)
    if pr.returncode != 0:
        errs.append('w%d: %s' % (i, (err or b'').decode('utf-8', 'ignore')[:150]))

st = state.load(T1)


def t_concurrent():
    assert not errs, '子进程失败: ' + str(errs)
    total = (len(st.get('tested', [])) + len(st.get('hypotheses', []))
             + len(st.get('why_log', [])))
    # notes 是追加型，4 个进程各追加一次
    notes_ok = (st.get('notes') or '').count('[') == 2
    assert total == 6, ('期望 6 条结构化记录（2+2+2），实际 %d: tested=%d hypo=%d why=%d'
                        % (total, len(st.get('tested', [])), len(st.get('hypotheses', [])), len(st.get('why_log', []))))
    assert notes_ok, 'notes 追加丢失，实际=%r' % (st.get('notes'),)


check('8 进程并发改不同字段 → 全部保留', t_concurrent)


print('\n=== G-15 冲突注入：旧 revision 不能覆盖新 revision ===')
T2 = '__v2_conflict__'
clean(T2)
state.save(T2, state.new_state(T2))
stale = state.load(T2)          # 拿到旧快照
state.mutate(T2, lambda s: s.__setitem__('stage', '被别人改了'))


def t_conflict():
    stale['stage'] = '我的旧改动'
    try:
        state.save(T2, stale)     # 不传 expect_revision，但内存 revision 比磁盘旧
    except state.ConcurrentModification as e:
        assert 'revision' in str(e).lower()
        return
    raise AssertionError('旧 revision 竟然覆盖成功了（应该被拒绝）')


check('旧 revision 写入被拒绝（ConcurrentModification）', t_conflict)


def t_expect():
    cur = state.load(T2)
    try:
        state.save(T2, cur, expect_revision=1)
    except state.ConcurrentModification:
        return
    raise AssertionError('expect_revision 不匹配却写入成功')


check('expect_revision 不匹配被拒绝', t_expect)


print('\n=== G-16 僵尸锁：区分 ESRCH 与 EPERM ===')
T3 = '__v2_lock__'
clean(T3)
state.save(T3, state.new_state(T3))
lp = state.path_of(T3) + '.lock'


def t_zombie_esrch():
    # 不存在的 PID -> ESRCH -> 应自动清理
    dead = 999999
    with open(lp, 'w', encoding='utf-8') as f:
        json.dump({'pid': dead, 'host': __import__('socket').gethostname(),
                   'started': None, 'token': 'zombie', 'at': time.time()}, f)
    t0 = time.time()
    with state.StateLock(state.path_of(T3)):
        pass
    assert time.time() - t0 < 3, '僵尸锁清理太慢'


check('ESRCH（进程不存在）→ 锁被自动清理', t_zombie_esrch)


def t_other_host():
    # 别的机器的锁 -> 不该动（会超时，而不是误删）
    with open(lp, 'w', encoding='utf-8') as f:
        json.dump({'pid': 1, 'host': 'some-other-host', 'started': None,
                   'token': 'other', 'at': time.time()}, f)
    try:
        with state.StateLock(state.path_of(T3), timeout=0.4):
            pass
        raise AssertionError('别的机器的锁竟然被抢了')
    except TimeoutError:
        pass
    finally:
        os.remove(lp)


check('别的主机的锁 → 不误删（超时等待）', t_other_host)


def t_token_release():
    # 释放时只删自己的锁
    with state.StateLock(state.path_of(T3)):
        pass
    assert not os.path.exists(lp), '锁未释放'
    # 伪造一个别人的锁，再开一个锁对象直接 __exit__，不该删掉它
    with open(lp, 'w', encoding='utf-8') as f:
        json.dump({'pid': 1, 'host': __import__('socket').gethostname(),
                   'started': None, 'token': 'not-mine', 'at': time.time()}, f)
    lk = state.StateLock(state.path_of(T3))
    lk.token = 'other-token'
    lk.__exit__()
    assert os.path.exists(lp), '把别人的锁删掉了！'
    os.remove(lp)


check('释放时只删自己的 token 对应的锁', t_token_release)


print('\n=== G-17 持久化：临时文件不残留 ===')
T4 = '__v2_persist__'
clean(T4)


def t_no_tmp():
    state.save(T4, state.new_state(T4))
    d = state.STATE_DIR
    base = os.path.basename(state.path_of(T4))
    leftovers = [f for f in os.listdir(d) if f.startswith(base + '.tmp')]
    assert not leftovers, '残留临时文件: ' + str(leftovers)


check('写盘后无残留临时文件', t_no_tmp)


def t_json_readable():
    st = state.load(T4)
    assert st is not None and st.get('target') == T4


check('写盘后 JSON 可正常读回', t_json_readable)


print('\n=== G-22 schema_version ===')
T5 = '__v2_schema__'
clean(T5)


def t_new_has_schema():
    state.save(T5, state.new_state(T5))
    st = state.load(T5)
    assert st.get('schema_version') == state.SCHEMA_VERSION, \
        'schema_version 应为 %s，实际 %r' % (state.SCHEMA_VERSION, st.get('schema_version'))


check('新状态带 schema_version=1', t_new_has_schema)


def t_future_reject():
    # 手工写一个"未来版本"的文件
    p = state.path_of(T5)
    d = json.load(open(p, encoding='utf-8'))
    d['schema_version'] = 99
    json.dump(d, open(p, 'w', encoding='utf-8'), ensure_ascii=False)
    # 直接调 _schema_check
    try:
        state._schema_check(d, T5)
    except ValueError as e:
        assert '99' in str(e) and '拒绝' in str(e)
        return
    raise AssertionError('未来版本没有被拒绝')


check('schema_version 高于支持版本 → 拒绝读取', t_future_reject)


def t_migrate():
    p = state.path_of(T5)
    old = {'target': T5, 'stage': '旧', 'tested': [{'what': 'x'}]}   # 无 schema_version
    json.dump(old, open(p, 'w', encoding='utf-8'), ensure_ascii=False)
    st = state.load(T5)
    # load 里如果没有自动迁移，至少 migrate() 要能工作
    if st.get('schema_version') is None:
        st = state.migrate(st, T5)
    assert st.get('schema_version') == state.SCHEMA_VERSION
    assert st.get('tested') == [{'what': 'x'}], '迁移不该丢数据'
    baks = [f for f in os.listdir(state.STATE_DIR) if f.startswith(os.path.basename(p) + '.schema')]
    assert baks, '迁移前应有备份，实际没有'


check('旧文件迁移：加版本字段、保留数据、留备份', t_migrate)


print('\n=== G-15 CLI 端到端（走子进程）===')


def t_cli():
    T6 = '__v2_cli__'
    clean(T6)
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    cmds = [
        [sys.executable, 'runs/tools/state.py', 'init', T6],
        [sys.executable, 'runs/tools/state.py', 'set', T6, '--stage', 'S1'],
        [sys.executable, 'runs/tools/state.py', 'tested', T6, '--what', 'w', '--result', 'r', '--verdict', '排除'],
        [sys.executable, 'runs/tools/state.py', 'budget', T6, '--used', '3', '--limit', '30'],
        [sys.executable, 'runs/tools/state.py', 'close', T6],
    ]
    for c in cmds:
        r = subprocess.run(c, cwd=os.getcwd(), capture_output=True, env=env, timeout=60)
        assert r.returncode == 0, '命令失败 %s: %s' % (c[3], (r.stderr or b'').decode('utf-8', 'ignore')[:200])
        assert '✅' in (r.stdout or b'').decode('utf-8', 'ignore'), '命令没有成功输出: %s' % c[3]
    st = state.load(T6)
    assert st['stage'] == 'S1'
    assert len(st['tested']) == 1
    assert st['budget']['used'] == 3
    assert len(st['rounds']) == 1
    assert st['revision'] >= 5


check('CLI init/set/tested/budget/close 全链路正常', t_cli)

print('\n结果: %d 通过 / %d 失败' % (passed, failed))
sys.exit(0 if failed == 0 else 1)
