#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
状态持久化 —— 靶标工作状态的单一真源。

问题：DSH 重启、上下文压缩后，"下一步做什么 / 卡在哪 / 试过什么"全丢，
     每次都要手写"接班说明"。这个文件把状态落到磁盘。

用法（PY 见 AGENTS §15）：
  "$PY" runs/tools/state.py list                        # 所有有状态的靶标
  "$PY" runs/tools/state.py show 某师范高校            # 打印可读状态（派活前必跑，粘进任务）
  "$PY" runs/tools/state.py init 某师范高校 --domain <子域>.<客户域名>
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
import shutil
import socket
import secrets
import sys
import time
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


def _proc_start_time(pid):
    """拿进程启动时间（Linux /proc/<pid>/stat 第 22 字段）。拿不到返回 None。

    用来区分"同一个 PID 被别的进程复用"：只有 PID 相同而启动时间不同，才判定为僵尸锁。
    """
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8", errors="replace") as f:
            parts = f.read().split()
        return parts[21] if len(parts) > 21 else None
    except Exception:
        return None


class StateLock:
    """跨进程独占锁（G-16 加固版）。

    锁文件内容：{pid, host, started, token, at}
    · 用 host 区分多机共享目录，别的机器的锁不碰
    · 用进程启动时间防 PID 复用（PID 被别的进程占用了，旧锁视为僵尸）
    · **区分 ESRCH 与 EPERM**：EPERM 说明进程还在，只是没权限查，绝不能删锁
    · 释放时只删 token 匹配的那个锁，避免误删别人新建的
    """

    def __init__(self, path, timeout=15.0):
        self.lock_path = path + '.lock'
        self.timeout = timeout
        self.token = secrets.token_hex(8)

    def _payload(self):
        return {
            'pid': os.getpid(),
            'host': socket.gethostname(),
            'started': _proc_start_time(os.getpid()),
            'token': self.token,
            'at': time.time(),
        }

    def _read(self):
        try:
            return json.load(open(self.lock_path, encoding='utf-8'))
        except Exception:
            return None

    def _is_stale(self):
        """True 表示可以安全清理。任何不确定的情况一律返回 False（保守）。"""
        info = self._read()
        if not info or not isinstance(info, dict):
            # 读不出来有两种可能：(a) 别人刚 os.open 创建、还没 os.write 的空文件；
            # (b) 真的是坏锁。误判 (a) 会导致两个进程同时进临界区、互相覆盖（实测丢数据）。
            # 保守策略：只有文件"存在超过 10 秒还读不出来"才当坏锁。
            try:
                age = time.time() - os.path.getmtime(self.lock_path)
            except FileNotFoundError:
                return True                  # 已经没了，直接重试
            except Exception:
                return False
            return age > 10
        host = info.get('host')
        if host and host != socket.gethostname():
            return False                     # 别的机器的锁，不碰
        pid = info.get('pid')
        if not isinstance(pid, int) or pid <= 0:
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:           # POSIX ESRCH：进程不存在
            return True
        except PermissionError:              # EPERM：进程还在，只是没权限
            return False
        except OSError as e:
            # Windows 上 os.kill(不存在的pid, 0) 抛的是 WinError 87/1168，不是 ProcessLookupError
            winerr = getattr(e, 'winerror', None)
            if winerr in (87, 1168):
                return True
            # 兜底：锁放了很久（>5 分钟）且 pid 探测失败，按僵尸处理
            at = info.get('at')
            if isinstance(at, (int, float)) and time.time() - at > 300:
                return True
            return False
        # 走到这里说明进程存活；再比对启动时间（Windows 上 /proc 不存在 -> None，跳过）
        if getattr(os, 'name', '') == 'nt':
            at = info.get('at')
            if isinstance(at, (int, float)) and time.time() - at > 300:
                return True
        # 进程存在：比对启动时间，防 PID 复用
        cur = _proc_start_time(pid)
        old = info.get('started')
        if cur is not None and old is not None and str(cur) != str(old):
            return True
        return False

    def __enter__(self):
        start = time.time()
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(fd, json.dumps(self._payload()).encode('utf-8'))
                    try: os.fsync(fd)
                    except Exception: pass
                finally:
                    os.close(fd)
                return self
            except FileExistsError:
                if self._is_stale():
                    # 删之前再看一眼 token 没变（防误删别人刚建的）
                    before = self._read()
                    time.sleep(0.01)
                    after = self._read()
                    if before and after and before.get('token') == after.get('token'):
                        try: os.remove(self.lock_path)
                        except FileNotFoundError: pass
                        continue
                if time.time() - start > self.timeout:
                    raise TimeoutError(
                        '拿不到状态锁 %s（等 %ds）。确认无其它进程在写后可手动删除该 .lock 文件。'
                        % (self.lock_path, int(self.timeout)))
                time.sleep(0.05)

    def __exit__(self, *a):
        info = self._read()
        if info and info.get('token') == self.token:
            try: os.remove(self.lock_path)
            except FileNotFoundError: pass

class ConcurrentModification(RuntimeError):
    """状态文件在本次修改期间被其他进程改过。"""


def _write_atomic(p, st):
    """原子写 + 持久化保证（G-17）。

    os.replace 只保证"要么旧要么新"，不保证断电后数据真的落了盘。
    这里补：临时文件 fsync -> rename -> 目录 fsync（让目录项也持久化）。
    """
    tmp = p + '.tmp.%d' % os.getpid()
    fd = None
    try:
        data = json.dumps(st, ensure_ascii=False, indent=1).encode('utf-8')
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
        os.write(fd, data)
        os.fsync(fd)                     # 数据落盘
        os.close(fd)
        fd = None
        os.replace(tmp, p)               # 原子替换
        try:                             # 目录项也持久化
            dfd = os.open(os.path.dirname(p) or '.', os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except Exception:
            pass
    finally:
        if fd is not None:
            try: os.close(fd)
            except Exception: pass
        if os.path.exists(tmp):          # 失败时别留垃圾临时文件
            try: os.remove(tmp)
            except Exception: pass

def mutate(target, fn):
    """读-改-写 全在锁内完成，避免并发覆盖。返回 fn 的返回值。

    fn(st) 直接改 st；fn 抛异常时不写盘。
    这是新的推荐用法，替代 load()→改→save() 的三段式。
    """
    p = path_of(target)
    os.makedirs(STATE_DIR, exist_ok=True)
    with StateLock(p):
        st = load(target)
        if st is None:
            raise FileNotFoundError('状态文件不存在: %s（先跑 init）' % path_of(target))
        before = int(st.get('revision', 0))
        result = fn(st)
        st['revision'] = before + 1
        st['updated_at'] = now_iso()
        _write_atomic(p, st)
        return result


def save(target, st, expect_revision=None):
    """写盘。加跨进程锁；给了 expect_revision 时做乐观锁校验。

    P1-06：不加锁的 read-modify-write 在多 agent 并发下会互相覆盖
    （A 读 rev=5 / B 读 rev=5 → 都写 rev=6 → 先写的丢失）。
    新代码优先用 mutate()，它把读-改-写整体放进同一把锁。
    """
    p = path_of(target)
    os.makedirs(STATE_DIR, exist_ok=True)
    with StateLock(p):
        disk_rev = 0
        if os.path.exists(p):
            try:
                disk_rev = int(json.load(open(p, encoding='utf-8')).get('revision', 0))
            except Exception:
                disk_rev = 0
        if expect_revision is not None and disk_rev != int(expect_revision):
            raise ConcurrentModification(
                '状态文件已被其他进程修改：磁盘 revision=%s，本次期望 revision=%s。'
                '请重新 load() 后再改，或用 mutate() 把读改写放进同一把锁。'
                % (disk_rev, expect_revision))
        if expect_revision is None and disk_rev > int(st.get('revision', 0)):
            # G-15：不再"警告后覆盖"。默认拒绝，逼调用方改用 mutate() 或重新 load。
            raise ConcurrentModification(
                '并发写入被拒绝：磁盘 revision=%s 高于内存 revision=%s。'
                '请重新 load() 后再改，或改用 mutate() 把读改写放进同一把锁。'
                % (disk_rev, st.get('revision', 0)))
        st['updated_at'] = now_iso()
        st['revision'] = max(disk_rev, int(st.get('revision', 0))) + 1
        _write_atomic(p, st)
    return p


SCHEMA_VERSION = 1


def _schema_check(st, target):
    """返回 ok / migrate；不兼容直接抛。"""
    v = st.get("schema_version")
    if v is None:
        return "migrate"
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError("%s: schema_version 不是整数（值=%r）" % (target, v))
    if v > SCHEMA_VERSION:
        raise ValueError(
            "%s: schema_version=%d 高于本程序支持的 %d，拒绝读取（请升级 state.py）"
            % (target, v, SCHEMA_VERSION))
    return "ok" if v == SCHEMA_VERSION else "migrate"


def migrate(st, target):
    """旧版本迁移：先备份，再改，最后验证。只做加法，不删字段。"""
    v = st.get("schema_version") or 0
    if v >= SCHEMA_VERSION:
        return st
    src = path_of(target)
    if os.path.exists(src):
        bak = src + ".schema%d.bak" % v
        try: shutil.copy2(src, bak)
        except Exception as e:
            sys.stderr.write("  [state] WARN 迁移备份失败: %s" % e)
    # v0 -> v1：补齐容器字段，不动已有数据
    for k, dv in (("hypotheses", []), ("tested", []), ("why_log", []),
                  ("rounds", []), ("blocked_by", []), ("notes", "")):
        st.setdefault(k, dv)
    st.setdefault("budget", {"used": 0, "limit": 0})
    st["schema_version"] = SCHEMA_VERSION
    # 迁移后验证
    if st.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("迁移失败：schema_version 未升到 %d" % SCHEMA_VERSION)
    return st


def new_state(target, domain=''):
    return {
        'schema_version': SCHEMA_VERSION,
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
    def _do(st):
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
                if b not in st.setdefault('blocked_by', []):
                    st['blocked_by'].append(b)
            ch.append('blocked_by+')
        if a.clear_blocked:
            st['blocked_by'] = []
            ch.append('blocked_by=')
        return ch
    try:
        ch = mutate(a.target, _do)
    except FileNotFoundError as e:
        print('[!] ' + str(e), file=sys.stderr); sys.exit(2)
    if not ch:
        print('没有要改的字段（用 --stage/--next/--notes/--add-blocked/--clear-blocked）')
        return
    print(f'✅ 已更新 {" ".join(ch)} → {path_of(a.target)}')

def cmd_hypo(a):
    if not a.id:
        print('[!] 需要 --id', file=sys.stderr); sys.exit(2)
    if a.state is not None and a.state not in HYPO_STATES:
        print(f'[!] state 只能是 {HYPO_STATES}', file=sys.stderr); sys.exit(2)

    def _do(st):
        hid = a.id
        h = next((x for x in st.setdefault('hypotheses', []) if x.get('id') == hid), None)
        created = h is None
        if created:
            h = {'id': hid, 'fingerprint': '', 'cves': [], 'verify_method': '',
                 'fail_signal': '', 'state': '未决', 'reason': ''}
            st['hypotheses'].append(h)
        for f, dest in (('fingerprint', 'fingerprint'), ('verify', 'verify_method'), ('fail', 'fail_signal')):
            v = getattr(a, f)
            if v is not None:
                h[dest] = v
        if a.cves is not None:
            h['cves'] = [x.strip() for x in a.cves.split(',') if x.strip()]
        if a.state is not None:
            h['state'] = a.state
        if a.reason is not None:
            h['reason'] = a.reason
        return (created, dict(h))
    try:
        created, h = mutate(a.target, _do)
    except FileNotFoundError as e:
        print('[!] ' + str(e), file=sys.stderr); sys.exit(2)
    print(f'✅ 假设 {a.id} {"新建" if created else "更新"}：{h["state"]} · {h["fingerprint"][:50]}')

def cmd_tested(a):
    if a.verdict not in VERDICTS:
        print(f'[!] verdict 只能是 {VERDICTS}', file=sys.stderr); sys.exit(2)

    def _do(st):
        st.setdefault('tested', []).append({
            'what': a.what, 'result': a.result, 'verdict': a.verdict, 'at': now_iso(),
        })
        return len(st['tested'])
    try:
        n = mutate(a.target, _do)
    except FileNotFoundError as e:
        print('[!] ' + str(e), file=sys.stderr); sys.exit(2)
    print(f'✅ 已记录：{a.verdict} · {a.what}（共 {n} 条）')

def cmd_budget(a):
    def _do(st):
        b = st.setdefault('budget', {'used': 0, 'limit': 0})
        if a.used is not None:
            b['used'] = int(a.used)
        if a.limit is not None:
            b['limit'] = int(a.limit)
        return (b['used'], b['limit'])
    try:
        used, limit = mutate(a.target, _do)
    except FileNotFoundError as e:
        print('[!] ' + str(e), file=sys.stderr); sys.exit(2)
    print(f'✅ 预算：{used}/{limit}')

def cmd_close(a):
    def _do(st):
        st.setdefault('rounds', []).append({
            'closed_at': now_iso(),
            'stage': st.get('stage', ''),
            'next_action': st.get('next_action', ''),
            'budget_used': (st.get('budget') or {}).get('used', 0),
            'blocked_by': list(st.get('blocked_by', [])),
            'open_hypotheses': [h['id'] for h in st.get('hypotheses', []) if h.get('state') == '未决'],
        })
        return len(st['rounds'])
    try:
        n = mutate(a.target, _do)
    except FileNotFoundError as e:
        print('[!] ' + str(e), file=sys.stderr); sys.exit(2)
    print(f'✅ 本轮收口已记录（第 {n} 轮）')

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
