/**
 * dsh-tool-guardrail —— 工具护栏（v0.2.0）
 *
 * 把「权限 / 数据量 / 审计」从 Prompt 约定升级为程序级机制。
 *
 * 依赖 DSH 的工具执行管道（源码依据见 runs/notes/DSH插件开发-工具管道.md）：
 *   tools/pre-execute → ctx.tools.guard(单调) → tools/execute → 工具本体
 *   → tools/post-execute → tools/result
 *
 * 设计原则（都是踩过的坑）：
 *   1. **插件自己绝不抛异常**：任何检查出错一律放行，不能让护栏把正常工具搞挂。
 *   2. **mode 默认 observe**：先只记录，看清真实调用什么样，再切 enforce。
 *   3. **不猜 agent 字段**：preset id 到底在 exec.agent 的哪一层没确认，
 *      所以把所有候选值拼成一个 identity blob 做子串匹配，同时记进探针日志供核对。
 *   4. **策略文件热加载**：改 guardrail-policy.json 不需要重启（按 mtime 缓存）。
 */

import fs from 'node:fs'

const name = 'tool-guardrail'
const inject = ['tools']

// 工作区路径：优先 ctx.config.workspace（profile 里配），其次环境变量，
// 最后自适应探测（找一个下面有 runs/tools 的目录），再不行用 cwd。
// 换机器时只要在 cordis.patch.yml 里写 config.workspace 即可，不用改代码。
let WS = ''   // 模块加载时立刻自适应一次（function 声明会提升，下面可用）
function defaultWs() {
  const cands = [
    process.env.GUARDRAIL_WS,
    process.env.DSH_WORKSPACE,
    process.cwd(),
    'C:/Users/admin/Documents/deepseek-harness/default-workspace',
  ].filter(Boolean)
  for (const c of cands) {
    try { if (fs.existsSync(c + '/runs/tools')) return c } catch (e) { /* next */ }
  }
  return process.cwd()
}
WS = defaultWs()   // 立刻求值：纯函数（loadScope/loadCfg）在 apply 之前被调用时也有正确路径

const POLICY_FILE = '/runs/tools/guardrail-policy.json'
const SCOPE_FILE = '/runs/tools/scope.json'
function policyPath() { return WS + POLICY_FILE }
function scopePath() { return WS + SCOPE_FILE }

// 哪个 profile 加载了我？用于区分"主 DSH 加载"和"实验 profile 加载"——
// 时间戳对比靠不住（实验 profile 可能比主进程还新），启动参数才是确定信息。
function profileOf() {
  try {
    const a = process.argv
    for (let i = 0; i < a.length; i++) {
      if (a[i] === '--profile' && a[i + 1]) return a[i + 1]
      if (a[i].startsWith('--profile=')) return a[i].slice(10)
    }
    return a.slice(0, 4).join(' ')
  } catch (e) { return 'unknown' }
}
const PROFILE = profileOf()
const PID = (typeof process !== 'undefined' && process.pid) || 0

// agentDeny 依赖 sessions + agentPresets；缺一个就只能靠 blob 兜底（而 blob 基本没用，因为
// Agent 接口只有 id）。启动自检发现缺失时置位，并在每条审计里带上，避免"看起来在管、其实没管"。
let AGENT_DENY_DEGRADED = false

// sessionId → presetId。agentPresets 只存在于 **agent 自己的 scope**，根 ctx 拿不到
// （实测主 DSH 里 ctx.get('agentPresets') === undefined，但 agent.ctx 里能拿到）。
// 所以靠 agent/created 事件建映射：
//   dsh-tool-schedule/src/index.ts:332
//     const agentPreset = agent.ctx.get('agentPresets')?.composedPreset(agent.ctx)
const PRESET_BY_SESSION = new Map()

// ── 策略加载（mtime 缓存，改文件即生效）──────────────────────────────
let _cfg = null
let _cfgMtime = 0
const DEFAULT_CFG = {
  enabled: true,
  mode: 'observe',
  auditLog: 'runs/guardrail-audit.jsonl',
  probeLog: 'runs/plugin-probe.log',
  probeMax: 300,
  agents: {},
  toolDeny: {},
  argMax: {},
  argDeny: [],
}

function loadCfg() {
  try {
    const m = fs.statSync(policyPath()).mtimeMs
    if (m !== _cfgMtime) {
      const raw = fs.readFileSync(policyPath(), 'utf8')
      _cfg = Object.assign({}, DEFAULT_CFG, JSON.parse(raw))
      _cfgMtime = m
    }
    return _cfg
  } catch (e) {
    // 配置读不到/坏了：用默认（observe + 空规则 = 全放行），并留痕
    if (_cfg === null) _cfg = Object.assign({}, DEFAULT_CFG)
    return _cfg
  }
}

// ── 日志（内存队列，异步 flush，绝不阻塞工具调用）─────────────────────
let _q = []
let _flushing = false
function enqueue(file, obj) {
  _q.push({ file, line: JSON.stringify(obj) })
  if (_q.length >= 40) flush()
  else if (!_flushing) {
    _flushing = true
    setTimeout(() => { _flushing = false; flush() }, 300)
  }
}
function flush() {
  if (_q.length === 0) return
  const batch = _q
  _q = []
  const byFile = {}
  for (const it of batch) (byFile[it.file] ||= []).push(it.line)
  for (const [rel, lines] of Object.entries(byFile)) {
    try {
      const p = WS + '/' + rel.replace(/^\/+/, '')
      fs.appendFileSync(p, lines.join('\n') + '\n', 'utf8')
    } catch (e) { /* 日志写不进去也不能影响工具 */ }
  }
}

// ── agent 身份提取（多路，不依赖单一字段）─────────────────────────────
function agentBlob(exec) {
  const out = []
  const push = (v) => {
    if (v === null || v === undefined) return
    if (typeof v === 'string' || typeof v === 'number') out.push(String(v))
  }
  const a = exec && exec.agent
  if (!a) return { blob: '', probes: null }
  push(a.id); push(a.name); push(a.role); push(a.kind); push(a.title)
  // 常见嵌套：options / session / meta / config。
  // 注意：不要碰 a.ctx —— 它是 Cordis 的 Context Proxy，属性访问/Object.keys 会触发 trap 抛异常，
  // 一旦抛出会让整个 evaluate() 挂掉，而外层 catch 会静默放行，
  // 表现为「agentDeny 完全不生效但也不报错」（2026-11-19 实测踩到）。
  for (const hk of ['options', 'session', 'meta', 'config']) {
    try {
      const holder = a[hk]
      if (!holder || typeof holder !== 'object') continue
      push(holder.preset); push(holder.presetId); push(holder.agentPreset)
      push(holder.name); push(holder.id); push(holder.role); push(holder.mode)
    } catch (e) { /* Proxy 拒绝访问就跳过，绝不让它冒泡 */ }
  }
  // 探针：把浅层结构留一份，重启后核对 preset id 到底在哪
  const probes = {}
  try {
    probes.agentKeys = Object.keys(a)
    for (const k of ['id', 'name', 'role', 'kind']) probes['agent.' + k] = a[k]
    for (const hk of ['options', 'session', 'meta', 'config']) {
      const h = a[hk]
      if (h && typeof h === 'object') {
        probes[hk + 'Keys'] = Object.keys(h).slice(0, 20)
        for (const k of ['preset', 'presetId', 'agentPreset', 'name', 'id', 'role']) {
          if (h[k] !== undefined) probes[hk + '.' + k] = h[k]
        }
      }
    }
  } catch (e) { probes.err = String(e && e.message) }
  return { blob: out.join(' | ').toLowerCase(), probes }
}

// ── 当前 agent 的 preset 精确查询（源码依据）────────────────────────
// dsh-agent/src/index.ts:260        super(ctx,'agents')       get(id: SessionId): Agent|undefined
// dsh-session/src/index.ts:1172     super(ctx,'sessions')     get(id: SessionId): Session|undefined
// dsh-agent-preset-registry:68      super(ctx,'agentPresets') presetForSession(session): string|null
// 这三条是从随包发布的 src/*.ts 读出来的，不是猜的。
function presetOfAgent(ctx, exec) {
  try {
    const sid = exec && exec.agent && exec.agent.id
    if (!sid) return null
    const mapped = PRESET_BY_SESSION.get(sid)      // ← 首选：agent/created 时从 agent.ctx 取的
    if (mapped) return mapped
    if (!ctx || typeof ctx.get !== 'function') return null
    const sessions = ctx.get('sessions')
    const presets = ctx.get('agentPresets')
    if (!sessions || !presets) return null
    const session = sessions.get(sid)
    if (!session) return null
    const pid = presets.presetForSession(session)
    return pid || null
  } catch (e) { return null }
}

// ── 授权范围校验（scope.json）────────────────────────────────────────
// scope 路径由 scopePath() 给出
let _scope = null
let _scopeMtime = 0
function loadScope() {
  try {
    const m = fs.statSync(scopePath()).mtimeMs
    if (m !== _scopeMtime) {
      _scope = JSON.parse(fs.readFileSync(scopePath(), 'utf8'))
      _scopeMtime = m
    }
    return _scope
  } catch (e) { return null }
}

const LOCAL_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|255\.)/
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g
const DOMAIN_RE = /(?<![a-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![a-z0-9-])/gi

// 从参数里抽域名/IP（递归，只取字符串）
function extractTargets(obj, out = { domains: new Set(), ips: new Set() }, depth = 0) {
  if (depth > 4 || obj === null || obj === undefined) return out
  if (typeof obj === 'string') {
    const s = obj
    for (const m of s.match(IPV4_RE) || []) out.ips.add(m)
    for (const m of s.match(DOMAIN_RE) || []) {
      const d = m.toLowerCase()
      if (d.includes('.') && !/^\d+\./.test(d)) out.domains.add(d)
    }
    return out
  }
  if (Array.isArray(obj)) { for (const v of obj) extractTargets(v, out, depth + 1); return out }
  if (typeof obj === 'object') {
    for (const v of Object.values(obj)) extractTargets(v, out, depth + 1)
    return out
  }
  return out
}

function ipInCidr(ip, cidr) {
  try {
    if (!cidr.includes('/')) return ip === cidr
    const [base, bitsStr] = cidr.split('/')
    const bits = parseInt(bitsStr, 10)
    const toInt = (x) => x.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
    return (toInt(ip) & mask) === (toInt(base) & mask)
  } catch (e) { return false }
}

/** 返回越界清单（空数组 = 全部在范围内或已放行） */
function outOfScope(args, scope) {
  if (!scope || !scope.targets) return []
  const { domains, ips } = extractTargets(args)
  const allowLocal = scope.allowLocal !== false
  const exclude = (scope.excludeDomains || []).map((x) => String(x).toLowerCase())

  const allDomains = []
  const allIps = []
  for (const t of Object.values(scope.targets)) {
    for (const d of t.domains || []) allDomains.push(String(d).toLowerCase())
    for (const i of t.ips || []) allIps.push(String(i))
  }

  const bad = []
  for (const d of domains) {
    if (exclude.some((x) => d === x || d.endsWith('.' + x))) continue
    if (allDomains.some((x) => d === x || d.endsWith('.' + x))) continue
    bad.push({ kind: 'domain', value: d })
  }
  for (const ip of ips) {
    if (allowLocal && LOCAL_RE.test(ip)) continue
    if (allIps.some((c) => ipInCidr(ip, c))) continue
    bad.push({ kind: 'ip', value: ip })
  }
  return bad
}

// ── 规则判定（返回 null = 放行）──────────────────────────────────────
function evaluate(exec, cfg, ctx) {
  const tool = String(exec && exec.name || '')
  const args = (exec && exec.arguments) || {}

  // ① 无条件工具拒绝
  if (cfg.toolDeny && Object.prototype.hasOwnProperty.call(cfg.toolDeny, tool)) {
    return { rule: 'toolDeny', reason: cfg.toolDeny[tool] || `工具 ${tool} 被策略禁止` }
  }

  // ② 按 agent 角色拒绝：优先用 presetId 精确匹配，拿不到才退回身份串模糊匹配
  const { blob, probes } = agentBlob(exec)
  if (cfg.agents) {
    const presetId = presetOfAgent(ctx, exec)          // 精确：agentPresets.presetForSession(session)
    const exactKey = presetId
      ? Object.keys(cfg.agents).find((k) => String(presetId).toLowerCase().includes(String(k).toLowerCase()))
      : null
    if (exactKey) {
      const rule = cfg.agents[exactKey]
      const deny = (rule && rule.deny) || []
      if (deny.includes(tool)) {
        return {
          rule: 'agentDeny', matched: exactKey, via: 'presetId:' + presetId,
          reason: rule.reason || `角色 ${exactKey} 不允许调用 ${tool}`,
          probes: { ...(probes || {}), presetId },
        }
      }
    } else if (blob) {
      // 兜底：拿不到 presetId（比如 sessions 服务没挂）时用身份串模糊匹配
      for (const [key, rule] of Object.entries(cfg.agents)) {
        if (!blob.includes(String(key).toLowerCase())) continue
        const deny = (rule && rule.deny) || []
        if (deny.includes(tool)) {
          return {
            rule: 'agentDeny', matched: key, via: 'blob',
            reason: rule.reason || `角色 ${key} 不允许调用 ${tool}`,
            probes,
          }
        }
      }
    }
  }

  // ③ 参数上限
  if (cfg.argMax) {
    for (const [argName, max] of Object.entries(cfg.argMax)) {
      const v = args[argName]
      if (typeof v === 'number' && typeof max === 'number' && v > max) {
        return { rule: 'argMax', matched: argName, reason: `参数 ${argName}=${v} 超过上限 ${max}（防一次拉全库）` }
      }
    }
  }

  // ③.5 授权范围（参数里的域名/IP 是否在 scope.json 内）
  const scope = loadScope()
  if (scope && scope.enforce !== undefined) {
    const bad = outOfScope(args, scope)
    if (bad.length && scope.enforce === true) {
      const what = bad.slice(0, 3).map((b) => b.value).join(', ')
      return { rule: 'outOfScope', matched: bad[0].value, reason: `目标不在授权范围内：${what}`, scopeHit: bad }
    }
    if (bad.length) {
      // observe：只留痕，靠 audit 里的 outOfScopeObserved 标记，不拦
      exec.__scopeObserved = bad.slice(0, 5)
    }
  }

  // ④ 工具+参数条件
  if (Array.isArray(cfg.argDeny)) {
    for (const r of cfg.argDeny) {
      if (!r || r.tool !== tool) continue
      const v = args[r.arg]
      if (typeof v === 'number' && typeof r.gt === 'number' && v > r.gt) {
        return { rule: 'argDeny', matched: r.arg, reason: r.reason || `${tool}.${r.arg}=${v} 超过 ${r.gt}` }
      }
    }
  }

  return null
}

function apply(ctx) {
  // 工作区路径：profile 的 config.workspace > 环境变量 > 自适应
  try {
    const c = ctx && ctx.config
    if (c && typeof c.workspace === 'string' && c.workspace) WS = c.workspace
  } catch (e) { /* ignore */ }
  if (!WS) WS = defaultWs()

  const cfg0 = loadCfg()
  // 启动标记：确认插件真的被加载、策略真的读到了
  enqueue(cfg0.probeLog, { t: Date.now(), tag: 'plugin-loaded', version: '0.8.2', profile: PROFILE, pid: PID, argv: process.argv.slice(0, 6), mode: cfg0.mode, enabled: cfg0.enabled, workspace: WS, policyExists: fs.existsSync(policyPath()), scopeExists: fs.existsSync(scopePath()) })

  // 启动自检：agentDeny 依赖 sessions + agentPresets 两个服务。
  // 如果它们不在，agentDeny 会静默退回 blob 兜底（或彻底失效）。
  // 与其等真实工具调用才发现，不如启动时就记一条。
  try {
    const probe = { t: Date.now(), tag: 'services-probe' }
    for (const svc of ['tools', 'sessions', 'agents', 'agentPresets', 'systemPrompt', 'redteam']) {
      let ok = false
      try { ok = !!(ctx && typeof ctx.get === 'function' && ctx.get(svc)) } catch (e) { ok = false }
      probe[svc] = ok
    }
    probe.guardAvailable = !!(ctx && ctx.tools && typeof ctx.tools.guard === 'function')
    probe.presetChain = !!(probe.sessions && probe.agentPresets)
    AGENT_DENY_DEGRADED = !probe.presetChain
    if (AGENT_DENY_DEGRADED) {
      probe.WARN = 'agentPresets/sessions 缺失：agentDeny 无法按角色精确匹配，会退回 blob 兜底（Agent 只有 id 时等于失效）'
    }
    enqueue(cfg0.probeLog, probe)
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'services-probe-failed', error: String(e && e.message) })
  }

  // ① 硬拒绝：guard 是单调的，返回字符串后没有后续监听器能翻案
  try {
    ctx.tools.guard((exec) => {
      try {
        const cfg = loadCfg()
        if (!cfg.enabled) return undefined
        const tool = String(exec && exec.name || '')
        const verdict = evaluate(exec, cfg, ctx)
        const { probes } = agentBlob(exec)

        // 审计：每个工具调用都记（含放行的），便于事后追
        enqueue(cfg.auditLog, {
          t: Date.now(),
          tool,
          callId: exec && exec.callId,
          rootCallId: exec && exec.rootCallId,
          mode: cfg.mode,
          decision: verdict ? 'deny' : 'allow',
          rule: verdict ? verdict.rule : null,
          matched: verdict ? verdict.matched : null,
          reason: verdict ? verdict.reason : null,
          outOfScopeObserved: exec && exec.__scopeObserved ? exec.__scopeObserved : null,
          agent: probes,
          presetId: presetOfAgent(ctx, exec),
          agentDenyDegraded: AGENT_DENY_DEGRADED || undefined,
        })
        // 探针：前 N 次把完整参数也留一份，用于核对字段与阈值是否合理
        enqueue(cfg.probeLog, {
          t: Date.now(), tag: 'guard', tool,
          args: exec && exec.arguments,
          probes,
        })

        if (verdict && cfg.mode === 'enforce') {
          // 返回 ToolGuardDenial（{reason, info}）而不是裸字符串：
          // 结构化 error info 会随结果持久化，便于面板/报告区分"被护栏拦"与"工具自己失败"
          return {
            reason: `[guardrail] ${verdict.reason}（规则 ${verdict.rule}${verdict.matched ? ':' + verdict.matched : ''}）`,
            info: { name: 'GuardrailDenied', code: 'GUARDRAIL_DENIED' },
          }
        }
        return undefined
      } catch (e) {
        return undefined // 护栏自己出错 -> 放行，绝不影响正常工具
      }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'guard-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'guard-register-failed', error: String(e && e.message) })
  }

  // ①.4 建立 sessionId → presetId 映射（agentPresets 只在 agent scope 里，必须借 agent.ctx）
  try {
    ctx.on('agent/created', ({ agent } = {}) => {
      try {
        if (!agent || !agent.id) return
        let pid = null
        try { pid = agent.ctx?.get('agentPresets')?.composedPreset(agent.ctx) ?? null } catch (e) { pid = null }
        if (pid) {
          PRESET_BY_SESSION.set(agent.id, pid)
          AGENT_DENY_DEGRADED = false
        }
        enqueue(cfg0.probeLog, {
          t: Date.now(), tag: 'agent-created',
          sessionId: agent.id, presetId: pid,
          hasCtx: !!agent.ctx,
          canGetPresets: !!(agent.ctx && typeof agent.ctx.get === 'function' && agent.ctx.get('agentPresets')),
        })
      } catch (e) {
        enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-failed', error: String(e && e.message) })
      }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-register-failed', error: String(e && e.message) })
  }

  // ①.5 延迟再探一次服务（apply 时很可能还没注册好——实测主 DSH 里 agents/agentPresets 都是 False）
  for (const delay of [5000, 20000]) {
    try {
      setTimeout(() => {
        try {
          const p2 = { t: Date.now(), tag: 'services-probe-late', delayMs: delay }
          for (const svc of ['tools', 'sessions', 'agents', 'agentPresets', 'redteam']) {
            let ok = false
            try { ok = !!(ctx && typeof ctx.get === 'function' && ctx.get(svc)) } catch (e) { ok = false }
            p2[svc] = ok
          }
          p2.presetChain = !!(p2.sessions && p2.agentPresets)
          if (p2.presetChain) AGENT_DENY_DEGRADED = false   // 后来居上：服务起来了就解除降级
          enqueue(cfg0.probeLog, p2)
        } catch (e) { /* ignore */ }
      }, delay)
    } catch (e) { /* ignore */ }
  }

  // ② 程序级审批 + 完整规则判定：tools/pre-execute 是 async waterfall，返回 {kind:'ask'} 会走人工确认
  //    签名依据 contracts.ts:18（Promise<PreToolDecision>）+ PreToolDecision 四态
  try {
    ctx.on('tools/pre-execute', async (exec, next) => {
      try {
        const cfg = loadCfg()
        if (!cfg.enabled) return next()
        const tool = String(exec && exec.name || '')
        const ap = cfg.approval || {}

        // ★ 先做完整规则判定（toolDeny / agentDeny / argMax / argDeny / outOfScope）。
        // 为什么必须放在这里：实测 ctx.tools.guard 在 profile 根 ctx 注册**收不到** agent 的工具调用
        // （审计里 result 57 条、pre-execute 1 条，guard 0 条）。pre-execute 才是实际生效的钩子。
        const verdict = evaluate(exec, cfg, ctx)
        const presetNow = presetOfAgent(ctx, exec)

        // ★ 无条件诊断：每次 pre-execute 都记一条，包含 agentDeny 判定需要的全部中间量。
        // 只在规则命中时记是看不见问题的——实测 list_agents 只有 result 记录、无从判断为什么没拦。
        try {
          const sid = exec && exec.agent && exec.agent.id
          const mapped = sid ? PRESET_BY_SESSION.get(sid) : undefined
          const agentsKeys = cfg.agents ? Object.keys(cfg.agents) : []
          const exactKey = presetNow
            ? agentsKeys.find((k) => String(presetNow).toLowerCase().includes(String(k).toLowerCase()))
            : null
          enqueue(cfg.probeLog, {
            t: Date.now(), tag: 'pre-execute-seen',
            tool: String(exec && exec.name || ''),
            agentId: sid ? String(sid).slice(0, 40) : null,
            mapSize: PRESET_BY_SESSION.size,
            mapped: mapped || null,
            presetNow: presetNow,
            agentsKeys,
            exactKey,
            deniedByRule: verdict ? verdict.rule : null,
            outcome: verdict ? (cfg.mode === 'enforce' ? 'deny' : 'would-deny') : 'pass',
          })
        } catch (e) {
          enqueue(cfg.probeLog, { t: Date.now(), tag: 'pre-execute-seen-failed', error: String(e && e.message) })
        }
        if (verdict) {
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, callId: exec && exec.callId,
            phase: 'pre-execute', decision: cfg.mode === 'enforce' ? 'deny' : 'would-deny',
            rule: verdict.rule, matched: verdict.matched, reason: verdict.reason,
            presetId: presetNow, via: verdict.via,
            outOfScopeObserved: exec && exec.__scopeObserved ? exec.__scopeObserved : null,
          })
          if (cfg.mode === 'enforce') {
            return {
              kind: 'deny',
              reason: `[guardrail] ${verdict.reason}（规则 ${verdict.rule}${verdict.matched ? ':' + verdict.matched : ''}）`,
              info: { name: 'GuardrailDenied', code: 'GUARDRAIL_DENIED' },
            }
          }
          return next()   // observe：记了 would-deny 就放行
        }

        // 规则没命中，再看是否要审批
        const needAsk = Array.isArray(ap.tools) && ap.tools.includes(tool)
        if (!needAsk) return next()

        enqueue(cfg.auditLog, {
          t: Date.now(), tool, callId: exec && exec.callId,
          phase: 'pre-execute', decision: cfg.mode === 'enforce' ? 'ask' : 'would-ask',
          rule: 'approval', reason: ap.reason || '高危动作需人工确认',
          presetId: presetNow,
        })
        if (cfg.mode !== 'enforce') return next()   // observe 模式只记录，不真的弹审批

        return {
          kind: 'ask',
          reason: `[guardrail] ${ap.reason || '该动作被列为需人工确认'}：${tool}`,
          displayReason: {
            en: `Guardrail approval required: ${tool}`,
            zh: `护栏要求人工确认：${tool}`,
          },
        }
      } catch (e) {
        return next()   // 审批逻辑出错 -> 不阻断
      }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'pre-execute-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'pre-execute-failed', error: String(e && e.message) })
  }

  // ③ 结果观察：记结论（成功/失败/耗时由调用方看时间戳差）
  try {
    ctx.on('tools/result', (exec, result) => {
      try {
        const cfg = loadCfg()
        enqueue(cfg.auditLog, {
          t: Date.now(),
          tool: exec && exec.name,
          callId: exec && exec.callId,
          isError: !!(result && result.isError),
          phase: 'result',
        })
      } catch (e) { /* ignore */ }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-failed', error: String(e && e.message) })
  }
}

export { name, inject, apply, evaluate, loadCfg, loadScope, outOfScope }
