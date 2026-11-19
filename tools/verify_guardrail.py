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
    probes = tail_json(PROBE)
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

    reg_guard = [p for p in probes if p.get('tag') == 'guard-registered']
    reg_result = [p for p in probes if p.get('tag') == 'result-hook-registered']
    fail_guard = [p for p in probes if p.get('tag') == 'guard-register-failed']
    check('guard 注册成功', bool(reg_guard) and not fail_guard,
          (fail_guard[-1].get('error') if fail_guard else ''))
    check('tools/result 钩子注册成功', bool(reg_result))

    # ③ 真实调用有没有流过来
    print('\n【3】真实工具调用（用 DSH 里随便做点事就会产生）')
    guards = [p for p in probes if p.get('tag') == 'guard']
    prex = [a for a in tail_json(AUDIT) if a.get('phase') == 'pre-execute']
    # 实测结论：ctx.tools.guard 在 profile 根 ctx 收不到 agent 的调用（审计里 result 57 条 / pre-execute 有 / guard 0 条），
    # 所以真正生效的钩子是 pre-execute。这里以 pre-execute 为准。
    check('pre-execute 收到了真实调用', bool(prex), f'{len(prex)} 条（guard 另记 {len(guards)} 条，已知为 0）')
    if guards:
        tools = {}
        for g in guards:
            tools[g.get('tool', '?')] = tools.get(g.get('tool', '?'), 0) + 1
        top = sorted(tools.items(), key=lambda x: -x[1])[:6]
        print('      最近调用的工具: ' + ', '.join(f'{k}×{v}' for k, v in top))

        # ④ agent 身份能不能识别（这是按角色拦截的前提）
        print('\n【4】agent 身份识别（按角色拦截的前提）')
        have_preset = 0
        sample = None
        for g in guards:
            pr = g.get('probes') or {}
            hit = [k for k in pr if any(w in k.lower() for w in ('preset', 'agent', 'role', 'name', 'id'))]
            if any(k.endswith('.preset') or k.endswith('.presetId') or k.endswith('.agentPreset') for k in pr):
                have_preset += 1
                if sample is None:
                    sample = pr
        check('agent 探针有数据', any((g.get('probes') or {}) for g in guards))
        if sample:
            print('      样例（preset 相关字段）: ' + json.dumps(
                {k: v for k, v in sample.items() if 'preset' in k.lower()}, ensure_ascii=False))
        else:
            print('      ⚠️  没找到 preset 字段，agent 探针样例: ' + json.dumps(
                (guards[-1].get('probes') or {}), ensure_ascii=False)[:300])

    # ④.5 agent/created 映射（agentDeny 的前提）
    print('【4.5】agent/created 映射（agentDeny 靠它拿 presetId）')
    created = [p for p in probes if p.get('tag') == 'agent-created']
    reg = [p for p in probes if p.get('tag') == 'agent-created-registered']
    check('agent/created 钩子已注册', bool(reg))
    if created:
        real = [c for c in created if c.get('presetId')]
        check('有真实 presetId 的 agent', bool(real), f'{len(real)}/{len(created)} 个')
        for c in created[-4:]:
            print(f"      sessionId={str(c.get('sessionId'))[:24]} presetId={c.get('presetId')} canGetPresets={c.get('canGetPresets')}")
        if not real:
            print("      ⚠️  全是 null → agent.ctx.get('agentPresets') 仍拿不到，agentDeny 会降级")
    else:
        print('      （还没有 agent 创建记录 —— 插件加载后每建一个子 agent 就会记一条）')

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
        check('审计条目字段完整', all('tool' in a and 'callId' in a for a in audit[-5:] if a.get('phase') != 'result'))

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
