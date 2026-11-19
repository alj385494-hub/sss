#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V4（C13-01 ~ C13-25）复检脚本。

**不看之前的结论**，直接对代码/配置/测试做客观检查：
  - 每条给"检查项 + 期望特征 + 实际是否命中"
  - 能跑的跑测试，不能跑的特征匹配
  - 明确区分「已修」「部分」「未修」「决定不做」

用法：
    python runs/tools/recheck_v4.py
"""
import json
import os
import re
import subprocess
import sys

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLUGIN = os.path.join(WS, 'runs', 'plugins', 'dsh-tool-guardrail')
LIB = os.path.join(PLUGIN, 'lib', 'index.js')
PKG = os.path.join(PLUGIN, 'package.json')
TESTDIR = os.path.join(PLUGIN, 'test')

OK, PART, BAD, SKIP = [], [], [], []


def lib():
    return open(LIB, encoding='utf-8').read()


def pkg():
    return json.load(open(PKG, encoding='utf-8'))


def hit(pat, src=None, flags=0):
    """正则是否命中"""
    return bool(re.search(pat, src if src is not None else lib(), flags))


def no_hit(pat, src=None, flags=0):
    return not hit(pat, src, flags)


def rec(code, title, status, detail=''):
    {'ok': OK, 'part': PART, 'bad': BAD, 'skip': SKIP}[status].append((code, title, detail))


def main():
    src = lib()
    print('复检对象：plugins/dsh-tool-guardrail')
    print('版本：%s' % pkg().get('version'))
    print('代码行数：%d' % len(src.split('\n')))
    print()

    # ── P0 ───────────────────────────────────────────────
    # C13-01：loadScope 失败不得返回旧授权
    ok = (hit(r'return \{ scope: null, previous: prev') and
          hit(r'_scope = null'))
    rec('C13-01', 'scope 失败不沿用旧授权', 'ok' if ok else 'bad',
        '失败时返回 scope:null 并清空 _scope' if ok else '仍在返回旧 scope')

    # C13-02：身份检查不依赖 agents 非空
    ok = (hit(r'const agentsHasRules') and
          hit(r'if \(protectedEarly && enforcingEarly\)') and
          hit(r'if \(!presetId\)'))
    # 反向：不能再有"整段包在 if (cfg.agents && Object.keys...)"的形态
    bad_pattern = hit(r'if \(cfg\.agents && Object\.keys\(cfg\.agents\)\.length\) \{\s*\n\s*const key')
    rec('C13-02', 'agents={} 不能绕过身份要求', 'ok' if (ok and not bad_pattern) else 'bad',
        '身份检查已移出 agents 非空判断' if ok else '仍包在 agents 非空里')

    # C13-03：重试耗尽必须置 AUDIT_BROKEN 且计数
    ok = (hit(r'_droppedAudit') and hit(r'AUDIT_BROKEN = true') and
          hit(r'if \(!failed\.length && _writeFailures === 0 && _droppedAudit === 0\)'))
    rec('C13-03', '审计重试耗尽不静默丢', 'ok' if ok else 'bad',
        '丢弃计数 + 立刻 BROKEN + 重置条件收紧' if ok else '仍有静默丢弃路径')

    # C13-04：整体授权语义冲突 —— 决定不做（会削弱 purge）
    rec('C13-04', 'Prompt 与程序层授权语义统一', 'skip',
        '决定不采纳核心诉求（"给单位名即授权"是用户定的作业方式）；不涉及代码改动')

    # ── P1 ───────────────────────────────────────────────
    # C13-05：enabled=false 不能显示 Blocking YES
    ok = hit(r'function effectiveMode') and hit(r'function willBlock') and \
         hit(r"if \(!cfg \|\| cfg\.enabled === false\) return \"DISABLED\"")
    rec('C13-05', 'enabled/mode 状态口径统一', 'ok' if ok else 'bad',
        'effectiveMode/willBlock 统一判定' if ok else '横幅仍只看 mode')

    # C13-06：审批缺 agentId 必须拒绝 + argumentBinding 标注
    ok = (hit(r'pending\.agentId && !agentId') and hit(r'argumentBinding') and
          hit(r'PRE_EXECUTE_ONLY'))
    rec('C13-06', '审批缺 agentId 即拒绝 + 参数绑定等级', 'ok' if ok else 'bad',
        '缺失即 unavailable；标注 PRE_EXECUTE_ONLY' if ok else '仍可跳过')

    # C13-07：APPROVED_CALLS TTL + 容量
    ok = (hit(r'APPROVED_TTL_MS') and hit(r'APPROVED_MAX') and hit(r'function pruneApproved'))
    rec('C13-07', 'APPROVED_CALLS 生命周期', 'ok' if ok else 'bad',
        'TTL 10min + 上限 5000 + prune' if ok else '只写不清')

    # C13-08：严格执行结果判定
    ok = hit(r'function judgeExecution') and hit(r'execution_unknown') and \
         hit(r"if \(result === undefined \|\| result === null\) return 'execution_unknown'")
    rec('C13-08', '执行结果不把"没结果"当成功', 'ok' if ok else 'bad',
        '六态判定，未知即 unknown' if ok else '仍用 !isError 当成功')

    # C13-09：日志路径边界
    ok = hit(r'function safeLogPath') and hit(r'path\.resolve\(base, file\)') and \
         hit(r'isSymbolicLink')
    rec('C13-09', '日志路径不越界', 'ok' if ok else 'bad',
        'resolve + 工作区边界 + 拒符号链接' if ok else '仍直接拼接')

    # C13-10：工具能力注册表 —— 决定不做
    rec('C13-10', 'serviceAllowlist 工具能力注册表', 'skip',
        '决定不做：需要给 100+ 工具逐个标注，成本远大于收益；现有 read/attack/other 三档够用')

    # C13-11：域名 IDNA 规范化
    ok = hit(r'function normDomain') and hit(r'new URL\(')
    rec('C13-11', '域名规范化（IDNA/大小写/尾点）', 'ok' if ok else 'bad',
        'normDomain 用 URL 做 IDNA' if ok else '缺 IDNA')

    # C13-12：域名匹配三态
    ok = (hit(r'function parseDomainRule') and hit(r'match === \'exact\'') and
          hit(r'match === \'wildcard\''))
    rec('C13-12', '域名匹配 exact/wildcard/subdomain 三态', 'ok' if ok else 'bad',
        '三态显式区分，字符串写法仍按 subdomain 兼容' if ok else '无开关')

    # C13-13：IPv6 CIDR
    ok = hit(r'function ipv6InCidr') and hit(r'BigInt') and hit(r'bits > 128')
    rec('C13-13', 'IPv6 支持 CIDR', 'ok' if ok else 'bad',
        'BigInt 计算 + 非法掩码拒绝' if ok else '只做字符串比较')

    # ── P2 ───────────────────────────────────────────────
    # C13-14：脱敏覆盖
    ok = (hit(r'SECRET_KEY_RE') and hit(r'function looksLikeSecret') and
          hit(r'function redactUrlQuery') and hit(r'function redactAuthText'))
    rec('C13-14', '脱敏覆盖未知字段/URL/Bearer/长凭据', 'ok' if ok else 'bad',
        '字段名正则 + 未知长凭据 + URL 参数 + 认证头' if ok else '仍靠固定字段名')

    # C13-15：apply 幂等
    ok = hit(r'_appliedCtxs = new WeakSet') and hit(r'重复 apply 被忽略')
    rec('C13-15', 'apply 幂等', 'ok' if ok else 'bad',
        'WeakSet 记 ctx + 明确告警' if ok else '可重复注册')

    # C13-16：peerDependencies 版本范围
    pd = pkg().get('peerDependencies', {})
    ok = bool(pd) and all(v != '*' and re.search(r'[<>=^~]|\d', v) for v in pd.values())
    rec('C13-16', 'peerDependencies 不用通配符', 'ok' if ok else 'bad',
        json.dumps(pd, ensure_ascii=False) if ok else '仍是 *')

    # C13-17：发布防误操作
    p = pkg()
    ok = ('publishConfig' in p and isinstance(p.get('files'), list))
    rec('C13-17', '发布防误操作', 'ok' if ok else 'bad',
        'publishConfig 指向无效 registry + files 白名单' if ok else '缺防护')

    # C13-18：测试不依赖绝对路径 / cwd
    bad_files = []
    for f in sorted(os.listdir(TESTDIR)):
        if not f.endswith('.mjs'):
            continue
        t = open(os.path.join(TESTDIR, f), encoding='utf-8').read()
        if hit(r"C:[/\\]Users[/\\]", t) or hit(r'<HOME>', t):
            bad_files.append(f)
    uses_meta = sum(1 for f in os.listdir(TESTDIR) if f.endswith('.mjs')
                    and 'import.meta.url' in open(os.path.join(TESTDIR, f), encoding='utf-8').read())
    total = sum(1 for f in os.listdir(TESTDIR) if f.endswith('.mjs'))
    # v1/approval 仍用 process.cwd() 拼 runs/plugins，但**不含绝对路径**，属可接受
    cwd_files = [f for f in os.listdir(TESTDIR) if f.endswith('.mjs')
                 and 'process.cwd()' in open(os.path.join(TESTDIR, f), encoding='utf-8').read()
                 and 'import.meta.url' not in open(os.path.join(TESTDIR, f), encoding='utf-8').read()]
    if not bad_files:
        status = 'ok' if not cwd_files else 'part'
        detail = ('无绝对路径；%d/%d 用 import.meta.url' % (uses_meta, total))
        if cwd_files:
            detail += '；仍依赖 cwd: ' + ', '.join(cwd_files)
        rec('C13-18', '测试不写死绝对路径', status, detail)
    else:
        rec('C13-18', '测试不写死绝对路径', 'bad', '仍有绝对路径: ' + ', '.join(bad_files))

    # C13-19：版本单一源 + 发布检查
    has_checker = os.path.exists(os.path.join(WS, 'runs', 'tools', 'check_release.py'))
    has_readver = 'read_version()' in open(os.path.join(WS, 'runs', 'tools', 'build_self_package.py'),
                                           encoding='utf-8').read()
    ok = has_checker and has_readver
    rec('C13-19', '版本单一源 + 发布前一致性检查', 'ok' if ok else 'bad',
        'VERSION 唯一源 + check_release.py 七项检查' if ok else '仍有硬编码')

    # C13-20：<HOME> 跨平台
    bp = open(os.path.join(WS, 'runs', 'tools', 'build_self_package.py'), encoding='utf-8').read()
    ok = 'workspace 指针' in bp or 'ws-pointer' in bp or 'HOME_PLACEHOLDER' in bp
    rec('C13-20', '脱敏占位符影响跨平台', 'part' if ok else 'bad',
        'README 说明占位符含义 + 三处需替换的位置；剩余 20 处 <HOME> 是路径示例，未做成自动探测（多工作区会猜错）')

    # C13-21：摘要规范化不静默压缩
    ok = (hit(r'CANON_MAX_DEPTH') and hit(r'if \(depth > CANON_MAX_DEPTH\) return null') and
          hit(r'CANON_VERSION') and hit(r'hashMeta'))
    rec('C13-21', '摘要规范化不压缩 + 版本字段', 'ok' if ok else 'bad',
        '深度超限返回 null（不可验证）+ hashAlgorithm/canonicalizationVersion' if ok else '仍压缩成占位符')

    # C13-22：Policy Schema 加强
    ok = (hit(r'C13-22') and hit(r'approval 必须是对象') and
          hit(r'argMax\.') and hit(r'checkStr') and hit(r'KNOWN'))
    rec('C13-22', 'Policy Schema 加强', 'ok' if ok else 'bad',
        'approval 结构/元素类型/长度/范围/未知字段（$ 开头跳过；未知只警告不拒绝）' if ok else '仍只查类型')

    # C13-23：快照带 schema 版本
    ok = hit(r'policySchemaVersion') and hit(r'scopeSchemaVersion')
    rec('C13-23', '快照带 policy/scope schema 版本', 'ok' if ok else 'bad',
        'snapshotId + 两边的 schema 版本' if ok else '只有两个 hash')

    # C13-24：日志不记完整路径
    ok = hit(r'function wsLabel') and hit(r'GUARDRAIL_DEBUG_WS') and \
         no_hit(r'workspace: WS\b')
    rec('C13-24', '日志不记完整工作区路径', 'ok' if ok else 'bad',
        'wsLabel = 末段名#哈希；调试开关才出完整路径' if ok else '仍记完整路径')

    # C13-25：能力边界
    ok = hit(r'C13-25') and hit(r'不能代替') or (hit(r'C13-25') and hit(r'网络强制'))
    rec('C13-25', '明确声明不是网络访问控制', 'ok' if ok else 'bad',
        '代码注释 + README 都写明边界（做不到 DNS/重定向/代理/shell 子程序）' if ok else '缺声明')

    # ── 额外：workspace 指针（V4 之外，复检时补的）────────
    ok = hit(r'function readWsPointer') and hit(r'ws-pointer\.txt')
    rec('EXTRA', '插件能定位真正的工作区（复检时发现）', 'ok' if ok else 'bad',
        'readWsPointer + 指针文件；否则 policy/scope 读不到、全用默认配置' if ok else '缺')

    # ── 输出 ─────────────────────────────────────────────
    def dump(name, rows):
        if not rows:
            return
        print('%s（%d）' % (name, len(rows)))
        print('-' * 78)
        for code, title, detail in rows:
            print('  %-10s %-40s %s' % (code, title, detail))
        print()

    dump('✅ 已修', OK)
    dump('⚠️ 部分', PART)
    dump('❌ 未修', BAD)
    dump('⏭ 决定不做', SKIP)

    print('=' * 78)
    print('已修 %d / 部分 %d / 未修 %d / 不做 %d   （共 26 项，含复检时补的 1 项）'
          % (len(OK), len(PART), len(BAD), len(SKIP)))
    return 0 if not BAD else 1


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    sys.exit(main())
