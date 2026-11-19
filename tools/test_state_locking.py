# -*- coding: utf-8 -*-
"""P1-06 并发覆盖测试：多进程同时改同一个 state，验证不丢改动。"""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.join(os.getcwd(), 'runs', 'tools'))
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass
import state

TARGET = '__concurrency_test__'
p = state.path_of(TARGET)

def cleanup():
    for f in (p, p + '.lock'):
        try: os.remove(f)
        except FileNotFoundError: pass

cleanup()
state.save(TARGET, state.new_state(TARGET))
print('  初始 revision:', state.load(TARGET)['revision'])

WORKER = r'''
import sys, os, time
sys.path.insert(0, os.path.join(os.getcwd(), 'runs', 'tools'))
import state
tag = sys.argv[1]
def add(st):
    time.sleep(0.02)                 # 放大竞态窗口
    st.setdefault('tested', []).append({'what': tag})
state.mutate('__concurrency_test__', add)
'''
wf = 'runs/tmp/_conc_worker.py'
open(wf, 'w', encoding='utf-8').write(WORKER)

# 8 个进程同时写
N = 8
procs = [subprocess.Popen([sys.executable, wf, 'w%d' % i], cwd=os.getcwd(),
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) for i in range(N)]
errs = []
for i, pr in enumerate(procs):
    out, err = pr.communicate(timeout=60)
    if pr.returncode != 0:
        errs.append('w%d: %s' % (i, (err or b'').decode('utf-8', 'ignore')[:200]))

st = state.load(TARGET)
got = sorted(x['what'] for x in st.get('tested', []))
ok = 0
print()
print('  并发写入 %d 个进程' % N)
print('  实际落盘条目:', got)
print('  revision:', st['revision'])

if errs:
    print('  X 子进程失败:', errs); ok = 1
if len(got) != N:
    print('  X 丢改动！期望 %d 条，实际 %d 条' % (N, len(got))); ok = 1
else:
    print('  OK 无丢失：%d 条全部保留' % N)
if st['revision'] != N + 1:
    print('  ! revision=%s（期望 %d，某些实现可能合并计数）' % (st['revision'], N + 1))

# 乐观锁测试
print()
print('  乐观锁：用旧 revision 写应该被拒')
st2 = state.load(TARGET)
rev = st2['revision']
state.mutate(TARGET, lambda s: s.setdefault('tested', []).append({'what': 'bump'}))
st2['tested'].append({'what': 'stale'})
try:
    state.save(TARGET, st2, expect_revision=rev)
    print('  X 没有拒绝过期写入'); ok = 1
except state.ConcurrentModification as e:
    print('  OK 正确拒绝:', str(e)[:80])
except Exception as e:
    print('  X 异常类型不对:', type(e).__name__, e); ok = 1

# 僵尸锁
print()
print('  僵尸锁：持有者进程已死 -> 应自动清掉')
lp = p + '.lock'
import json as _j, socket as _s
open(lp, 'w').write(_j.dumps({'pid': 999999, 'host': _s.gethostname(), 'started': None, 'token': 'zombie', 'at': __import__('time').time() - 3600}))
t0 = time.time()
try:
    state.mutate(TARGET, lambda s: s.setdefault('tested', []).append({'what': 'zombie'}))
    print('  OK 自动清理僵尸锁，耗时 %.2fs' % (time.time() - t0))
except Exception as e:
    print('  X 僵尸锁未清理:', e); ok = 1

cleanup()
print()
print('结果:', 'ALL PASS' if ok == 0 else 'FAIL')
sys.exit(ok)
