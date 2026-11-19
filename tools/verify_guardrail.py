#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dsh-tool-guardrail 运行时验证 —— 重启后一条命令验完。

为什么需要它：插件逻辑已经单测过（12/12 + enforce 4/4），但那测的是**函数**。
这里测的是**DSH 进程里真正加载的插件**：它有没有被加载、guard 有没有注册、
agent 身份能不能识别、审计有没有落盘、规则有没有真的触发。

用法（PY 见 AGENTS §15）：
  "$PY" runs/tools/verify_guardrail.py

退出码 0 = 全通过；1 = 有问题。
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from verify_change import dsh_started_at  # 复用取进程启动时间的实现

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
def _all_probe_paths():
    """插件的 WS 可能不是本工作区（它 fallback 到 process.cwd()）。
    两处都看，避免"看到旧日志以为插件没加载"——2026-11-19 实际踩到过。"""
    cands = [os.path.join(WS, 'runs', 'plugin-probe.log')]
    try:
        import glob
        cands += glob.glob(os.path.expanduser('~/.dsh/profiles/*/runs/plugin-probe.log'))
    except Exception:
        pass
    return [c for c in cands if os.path.exists(c)]


def load_probe_merged():
    """合并多处 probe 日志，按时间排序。"""
    rows = []
    for f in _all_probe_paths():
        try:
            for ln in open(f, encoding='utf-8'):
                ln = ln.strip()
                if ln:
                    try:
                        rows.append(json.loads(ln))
                    except Exception:
                        pass
        except Exception:
            pass
    rows.sort(key=lambda r: r.get('t', 0))
    return rows


PROBE = os.path.join(WS, 'runs', 'plugin-probe.log')
AUDIT = os.path.join(WS, 'runs', 'guardrail-audit.jsonl')
POLICY = os.path.join(WS, 'runs', 'tools', 'guardrail-policy.json')
PLUGIN = os.path.expanduser('~/.dsh/profiles/desktop/node_modules/dsh-tool-guardrail/lib/index.js')

ok = 0
bad = 0


def check(label, cond, detail=''):
    global ok, bad
    if cond:
        print(f'  ✅ {label}' + (f'  {detail}' if detail else ''))
        ok += 1
    else:
        print(f'  ❌ {label}' + (f'  {detail}' if detail else ''))
        bad += 1


def tail_json(path, n=400):
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-n:]




# ── G-06：真实负向验证 ─────────────────────────────────────────────
# 为什么需要：以前的验证只查"插件加载了吗"，从未证明"该拦的真拦住了"。
# 一个能加载但拦不住的护栏，比没有护栏更坏（虚假安全感）。
#
# 两段式，因为脚本无法代替模型调用工具：
#   1) --neg-prepare <tool>  把模式切到 enforce、把该工具加进 toolDeny
#   2) 模型真的调用那个工具，应收到 "[guardrail] ..." 的 Error
#   3) --neg-verify <tool>   查审计里有没有 deny 记录，然后自动恢复配置


def _policy_path():
    return POLICY


def neg_prepare(tool):
    import json as _json
    import shutil as _sh
    bak = POLICY + '.bak-negtool'
    if not os.path.exists(bak):
        _sh.copy2(POLICY, bak)
    d = _json.load(open(POLICY, encoding='utf-8'))
    d['mode'] = 'enforce'
    td = d.get('toolDeny') or {}
    td[tool] = 'G-06 负向验证：这条必须被拦住'
    d['toolDeny'] = td
    _json.dump(d, open(POLICY, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print('已准备负向验证：mode=enforce, toolDeny[%s] 已设置' % tool)
    print('下一步：让模型真的调用 %s，期望收到 "[guardrail] ..." 的 Error。' % tool)
    print('然后运行： verify_guardrail.py --neg-verify %s' % tool)
    return 0


def neg_verify(tool):
    import json as _json
    import shutil as _sh
    rows = tail_json(AUDIT)
    hits = [r for r in rows if r.get('tool') == tool
            and r.get('phase') == 'pre-execute'
            and r.get('decision') == 'deny']
    ok = bool(hits)
    print('=' * 62)
    print('G-06 负向验证结果')
    print('=' * 62)
    if ok:
        h = hits[-1]
        print('  ✅ 该工具确实被拦住了')
        print('     规则: %s' % h.get('rule'))
        print('     理由: %s' % h.get('reason'))
        print('     presetId: %s' % h.get('presetId'))
    else:
        print('  ❌ 审计里没有 %s 的 deny 记录' % tool)
        print('     要么没有真的调用它，要么护栏没拦住（后者是严重问题）')
    bak = POLICY + '.bak-negtool'
    if os.path.exists(bak):
        _sh.move(bak, POLICY)
        print('  已恢复原策略: %s' % POLICY)
    else:
        print('  ⚠️  没找到备份 %s，请手动检查 mode 是否已恢复' % bak)
    return 0 if ok else 1


def reset_logs():
    """重启前清空日志，让验证从干净状态开始（避免测试污染混进来）。"""
    import os as _os
    for f in (PROBE, AUDIT):
        if _os.path.exists(f):
            _os.remove(f)
            print(f'  已清空 {f}')
        else:
            print(f'  （不存在）{f}')


def main():
    if '--reset' in sys.argv:
        reset_logs()
        print('日志已清空。现在请重启 DSH，然后不带参数跑本脚本。')
        return 0
    if '--neg-prepare' in sys.argv:
        i = sys.argv.index('--neg-prepare')
        tool = sys.argv[i + 1] if i + 1 < len(sys.argv) else 'get_goal'
        return neg_prepare(tool)
    if '--neg-verify' in sys.argv:
        i = sys.argv.index('--neg-verify')
        tool = sys.argv[i + 1] if i + 1 < len(sys.argv) else 'get_goal'
        return neg_verify(tool)
    print('=' * 66)
    print('dsh-tool-guardrail 运行时验证')
    print('=' * 66)

    # ① 文件与配置
    print('\n【1】文件与策略')
    check('插件已部署到 profile', os.path.exists(PLUGIN), PLUGIN.replace(os.path.expanduser('~'), '~'))
    check('策略文件存在', os.path.exists(POLICY))
    policy = {}
    if os.path.exists(POLICY):
        try:
            policy = json.load(open(POLICY, encoding='utf-8'))
        except Exception as e:
            check('策略 JSON 可解析', False, str(e))
    if policy:
        check('策略可解析', True, f"mode={policy.get('mode')} enabled={policy.get('enabled')}")
        check('mode 是合法值', policy.get('mode') in ('observe', 'enforce'), str(policy.get('mode')))

    # ② 插件是否真的被加载
    print('\n【2】插件加载（重启后才会有）')
    probes = load_probe_merged()
    loaded = [p for p in probes if p.get('tag') == 'plugin-loaded']
    started = dsh_started_at()
    now_ms = time.time() * 1000
    # 只有"主 DSH 启动之后写的"才算主进程加载成功；实验 profile 的启动也会写这份日志
    # 以启动参数里的 profile 为准（时间戳不可靠：实验 profile 可能比主进程还新）
    prof = str(loaded[-1].get('profile', '')).strip() if loaded else ''
    # Electron 启动时没有 --profile 参数，argv 里带的是 profiles\desktop 这样的路径
    from_main = bool(loaded) and ('profiles' + chr(92) + 'desktop' in prof
                                 or 'profiles/desktop' in prof
                                 or prof == 'desktop')
    check('probe 日志有 plugin-loaded', bool(loaded),
          f"version={loaded[-1].get('version')} mode={loaded[-1].get('mode')}" if loaded else '—— 插件没跑起来 → 是否还没重启？')
    if loaded:
        check('这份日志是 desktop profile（主 DSH）加载的', from_main,
              f"profile={loaded[-1].get('profile')}" if from_main
              else f"profile={loaded[-1].get('profile')} → 实验 profile 写的，主 DSH 还没加载")

    # v1.0 起移除 ctx.tools.guard（实测收不到 agent 调用），拦截点是 pre-execute
    reg_pre = [p for p in probes if p.get('tag') == 'pre-execute-registered']
    reg_result = [p for p in probes if p.get('tag') == 'result-hook-registered']
    fail_pre = [p for p in probes if p.get('tag') == 'pre-execute-failed']
    check('pre-execute 注册成功', bool(reg_pre) and not fail_pre,
          (fail_pre[-1].get('error') if fail_pre else ''))
    check('tools/result 钩子注册成功', bool(reg_result))

    # ③ 真实调用有没有流过来
    print('\n【3】真实工具调用（用 DSH 里随便做点事就会产生）')
    # 诊断写在 probe 的 pre-execute-seen；audit 的 phase=pre-execute 只在规则命中时才写
    seen = [p for p in probes if p.get('tag') == 'pre-execute-seen']
    prex = seen
    # 实测结论：ctx.tools.guard 在 profile 根 ctx 收不到 agent 的调用（审计里 result 57 条 / pre-execute 有 / guard 0 条），
    # 所以真正生效的钩子是 pre-execute。这里以 pre-execute 为准。
    check('pre-execute 收到了真实调用', bool(prex), f'{len(prex)} 条')
    if prex:
        tools = {}
        for g in prex:
            tools[g.get('tool', '?')] = tools.get(g.get('tool', '?'), 0) + 1
        top = sorted(tools.items(), key=lambda x: -x[1])[:6]
        print('      最近调用的工具: ' + ', '.join(f'{k}×{v}' for k, v in top))


    # ④ agent 身份（v1.0：看 pre-execute-seen 里的 presetId，不再 dump agentBlob）
    print('【4】agent 身份识别（按角色拦截的前提）')
    with_preset = [p for p in prex if p.get('presetId')]
    check('pre-execute-seen 里带 presetId', bool(with_preset), f'{len(with_preset)}/{len(prex)} 条')
    if with_preset:
        sample = with_preset[-1]
        print(f"      样例: tool={sample.get('tool')} presetId={sample.get('presetId')} outcome={sample.get('outcome')}")

    # ⑤ 审计日志
    print('\n【5】审计日志')
    audit = tail_json(AUDIT)
    check('审计日志有记录', bool(audit), f'{len(audit)} 条')
    if audit:
        denies = [a for a in audit if a.get('decision') == 'deny']
        allows = [a for a in audit if a.get('decision') == 'allow']
        print(f'      allow={len(allows)}  deny={len(denies)}')
        for d in denies[:3]:
            print(f'      拒绝样例: {d.get("tool")} ← {d.get("reason")}')
            # 只有工具调用类记录才要求 tool+callId；policy-reload / approval 是策略与审批事件，没有这些字段
    tool_rows = [a for a in audit[-20:] if a.get('phase') in ('pre-execute', 'result', 'execution')]
    check('审计条目字段完整', all('tool' in a and 'callId' in a for a in tool_rows),
          f'{len(tool_rows)} 条工具调用记录')

    # ⑥ 结论与下一步
    print('\n' + '=' * 66)
    if bad == 0:
        print(f'✅ 全通过（{ok} 项）')
        if policy.get('mode') == 'observe':
            print('   当前 observe：只记录不拦截。看一轮 audit 里有没有误伤，再改 mode=enforce。')
    else:
        print(f'❌ {bad} 项未通过 / {ok} 项通过')
        if not loaded:
            print('   最可能的原因：DSH 还没重启（插件在启动时才加载）。')
        print(f'   回滚：cp runs/backup/cordis.patch.yml.bak-guardrail-* ~/.dsh/profiles/desktop/cordis.patch.yml')
    print('=' * 66)
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
