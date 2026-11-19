/**
 * dsh-tool-guardrail v1.1.0 —— 工具护栏
 *
 * 把「工具权限 / 授权范围 / 参数校验 / 审计」从 Prompt 约定升级为程序级机制。
 *
 * 依赖 DSH 的工具执行管道（源码依据见 docs/dispatch/DSH插件开发-工具管道.md）：
 *   tools/pre-execute → ctx.tools.guard → tools/execute → 工具本体 → tools/post-execute → tools/result
 *
 * 实测结论（不是推测，来自真实运行时数据）：
 *   · `ctx.tools.guard` 在 profile 根 ctx **收不到** agent 的工具调用（scope 注册层向下继承）
 *   · `tools/pre-execute` 是**实际生效**的拦截点（事件向上扩展）
 *   · `Agent` 接口只有 `id`；preset 必须借 `agent.ctx.get('agentPresets').composedPreset(agent.ctx)`
 *     在 `agent/created` 事件里取，建成 sessionId→presetId 映射
 *
 * v1.1.0 相对 v0.8.2 的变更（对应第二轮审计 P0/P1）：
 *   P0-01 Fail-Open → 分级 Fail-Safe（NORMAL / DEGRADED / BLOCKED）
 *   P0-02 启动时明确打印「是否真的会拦」
 *   P0-03 scope 的 expires / allowUnlisted 真正生效；serviceAllowlist 与授权目标分离；支持 IPv6 字面量
 *   P0-04 agent 权限支持 allow 白名单模式；presetId 改为边界匹配（不再裸 includes）
 *   P1-01 参数校验递归 + 数字字符串
 *   P1-03 日志脱敏（敏感 key 与 Bearer/password= 一律打码）+ 队列上限 + 写失败告警
 *   P1-04 session 映射加 TTL 与清理
 *   P1-05 策略热加载改用**内容哈希**（mtime 精度不可靠），坏配置保留上一份有效策略
 *
 * 明确不做的（能力边界，不是遗漏）：
 *   · DNS 解析 / CNAME 链 / 重定向后目标 / 代理出口 / 最终连接 IP —— 插件在 pre-execute，
 *     只能看到工具**参数**，看不到工具内部的网络行为。声称能拦这些就是虚假安全感。
 *   · 审批结果的回调消费 —— 需先确认 DSH 的 approval API 是否暴露结果事件。
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import net from 'node:net'

const name = 'tool-guardrail'
const inject = ['tools']

// ── 安全状态（P0-01）────────────────────────────────────────────────
const STATE = { NORMAL: 'NORMAL', DEGRADED: 'DEGRADED', BLOCKED: 'BLOCKED' }

const DEFAULT_PROTECTED = [
  // 策略文件坏了也要拦住的高危动作（硬编码兜底，不依赖配置）
  'redteam_webshell_add', 'redteam_tunnel_add', 'redteam_credential_add',
  'redteam_score_hit', 'redteam_access_add', 'redteam_cleanup',
  'redteam_data_proof', 'redteam_engagement_open',
]

// ── 工作区路径 ──────────────────────────────────────────────────────
let WS = ''
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
const POLICY_FILE = '/runs/tools/guardrail-policy.json'
const SCOPE_FILE = '/runs/tools/scope.json'
function policyPath() { return WS + POLICY_FILE }
function scopePath() { return WS + SCOPE_FILE }

WS = defaultWs()

function profileOf() {
  try {
    const a = process.argv
    for (let i = 0; i < a.length; i++) {
      if (a[i] === '--profile' && a[i + 1]) return a[i + 1]
      if (a[i].startsWith('--profile=')) return a[i].slice(10)
    }
    const joined = a.join(' ')
    const m = joined.match(/profiles[\\/]([A-Za-z0-9_-]+)/)
    if (m) return m[1]
    return a.slice(0, 4).join(' ')
  } catch (e) { return 'unknown' }
}
const PROFILE = profileOf()
const PID = (typeof process !== 'undefined' && process.pid) || 0

// ── 脱敏（P1-03）────────────────────────────────────────────────────
const SENSITIVE_KEY = /^(pass(word|wd)?|pwd|token|access_?token|refresh_?token|id_?token|authorization|auth|cookie|set-?cookie|secret|client_?secret|api_?key|apikey|private_?key|credential|session|sessdata|bili_jct|csrf|xsrf|sign|signature)$/i
const SENSITIVE_INLINE = [
  /(bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/gi,
  /((?:pass(?:word|wd)?|pwd|token|secret|api_?key|authorization|sessdata|bili_jct)\s*[:=]\s*)([^\s"'&,;}]{4,})/gi,
  /(cookie\s*:\s*)([^\r\n]{4,})/gi,
]
const REDACT = '[REDACTED]'

function redactValue(v, depth = 0) {
  if (v === null || v === undefined) return v
  if (depth > 6) return '[deep]'
  if (typeof v === 'string') {
    if (v.length > 400) return v.slice(0, 400) + '…[truncated ' + v.length + ']'
    let s = v
    for (const re of SENSITIVE_INLINE) s = s.replace(re, (m, p1) => p1 + REDACT)
    return s
  }
  if (typeof v !== 'object') return v
  if (Array.isArray(v)) return v.slice(0, 20).map((x) => redactValue(x, depth + 1))
  const out = {}
  let k = 0
  for (const key of Object.keys(v)) {
    if (k++ > 40) { out['…'] = 'truncated'; break }
    out[key] = SENSITIVE_KEY.test(key) ? REDACT : redactValue(v[key], depth + 1)
  }
  return out
}
function argsHash(args) {
  try {
    return 'sha256:' + crypto.createHash('sha256')
      .update(JSON.stringify(redactValue(args))).digest('hex').slice(0, 16)
  } catch (e) { return null }
}

// ── 日志（P1-03：队列上限 + 写失败告警 + 退出 flush）────────────────
const QUEUE_MAX = 2000
let _q = []
let _flushing = false
let _writeFailures = 0
let _dropped = 0

function enqueue(file, obj) {
  if (_q.length >= QUEUE_MAX) {
    _dropped += 1
    if (_dropped === 1 || _dropped % 100 === 0) {
      process.stderr.write('[guardrail] WARN 日志队列已满，累计丢弃 ' + _dropped + ' 条\n')
    }
    return
  }
  _q.push({ file, line: JSON.stringify(obj) })
  if (_q.length >= 50) flush()
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
      _writeFailures = 0
    } catch (e) {
      _writeFailures += 1
      // 写不进去必须让人看见，不能静默（P1-03 要求）
      if (_writeFailures <= 3) {
        process.stderr.write('[guardrail] ERROR 审计日志写入失败: ' + String(e && e.message) +
          '（已连续失败 ' + _writeFailures + ' 次）\n')
      }
    }
  }
}

// 进程退出时尽力 flush
for (const ev of ['exit', 'SIGINT', 'SIGTERM']) {
  try { process.on(ev, () => { try { flush() } catch (e) { /* last resort */ } }) } catch (e) { /* ignore */ }
}

// ── 策略加载（P1-05：内容哈希 + 坏配置不覆盖好配置）──────────────────
const DEFAULT_CFG = {
  enabled: true,
  mode: 'observe',
  policyVersion: 'unknown',
  auditLog: 'runs/guardrail-audit.jsonl',
  probeLog: 'runs/plugin-probe.log',
  agents: {},
  toolDeny: {},
  argMax: {},
  argDeny: [],
  approval: { tools: [] },
  protectedTools: [],
}
let _cfg = null
let _cfgHash = null
let _cfgError = null

function loadCfg() {
  try {
    const raw = fs.readFileSync(policyPath(), 'utf8')
    const h = crypto.createHash('sha256').update(raw).digest('hex')
    if (h === _cfgHash && _cfg) return { cfg: _cfg, error: null, fresh: false }
    // 内容变了（或首次）：先解析，成功才替换
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      _cfgError = 'policy JSON 解析失败: ' + String(e && e.message)
      // P0-01：坏配置不覆盖上一份有效策略；没有有效策略时进入 BLOCKED
      if (_cfg) return { cfg: _cfg, error: _cfgError, fresh: false, stale: true }
      return { cfg: Object.assign({}, DEFAULT_CFG), error: _cfgError, fresh: false, broken: true }
    }
    _cfg = Object.assign({}, DEFAULT_CFG, parsed)
    _cfgHash = h
    _cfgError = null
    return { cfg: _cfg, error: null, fresh: true }
  } catch (e) {
    const msg = 'policy 读取失败: ' + String(e && e.message)
    _cfgError = msg
    if (_cfg) return { cfg: _cfg, error: msg, fresh: false, stale: true }
    return { cfg: Object.assign({}, DEFAULT_CFG), error: msg, fresh: false, broken: true }
  }
}

// ── scope 加载（P1-05 同款：内容哈希 + 坏文件不覆盖）──────────────────
let _scope = null
let _scopeHash = null
let _scopeError = null

function loadScope() {
  try {
    const raw = fs.readFileSync(scopePath(), 'utf8')
    const h = crypto.createHash('sha256').update(raw).digest('hex')
    if (h === _scopeHash) return { scope: _scope, error: _scopeError }
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      _scopeError = 'scope JSON 解析失败: ' + String(e && e.message)
      return { scope: _scope, error: _scopeError, broken: true }
    }
    _scope = parsed
    _scopeHash = h
    _scopeError = null
    return { scope: _scope, error: null }
  } catch (e) {
    _scopeError = 'scope 读取失败: ' + String(e && e.message)
    return { scope: _scope, error: _scopeError, missing: true }
  }
}

// ── agent 身份映射（P1-04：TTL + 清理）──────────────────────────────
const PRESET_BY_SESSION = new Map()   // sessionId -> { presetId, at }
// pre-execute 返回 ask 时把参数摘要存这里，供 approval/request 用 callId 关联
// （ApprovalRequest 里没有 arguments，拿不到参数哈希）
const PENDING_APPROVAL = new Map()   // callId -> { argsHash, target, presetId, at }
const SESSION_TTL_MS = 6 * 60 * 60 * 1000   // 6 小时没更新就视为失效

function rememberSession(sessionId, presetId) {
  if (!sessionId) return
  PRESET_BY_SESSION.set(sessionId, { presetId, at: Date.now() })
}
function forgetSession(sessionId) {
  if (sessionId && PRESET_BY_SESSION.delete(sessionId)) {
    enqueue((_cfg || DEFAULT_CFG).probeLog, { t: Date.now(), tag: 'session-forgotten', sessionId })
  }
}
function lookupPreset(sessionId) {
  if (!sessionId) return null
  const hit = PRESET_BY_SESSION.get(sessionId)
  if (!hit) return null
  if (Date.now() - hit.at > SESSION_TTL_MS) {
    PRESET_BY_SESSION.delete(sessionId)
    return null
  }
  return hit.presetId || null
}
function sweepSessions() {
  const now = Date.now()
  let n = 0
  for (const [k, v] of PRESET_BY_SESSION) {
    if (now - v.at > SESSION_TTL_MS) { PRESET_BY_SESSION.delete(k); n += 1 }
  }
  return n
}

function presetOfAgent(ctx, exec) {
  try {
    const sid = exec && exec.agent && exec.agent.id
    if (!sid) return null
    const mapped = lookupPreset(sid)
    if (mapped) return mapped
    if (!ctx || typeof ctx.get !== 'function') return null
    const sessions = ctx.get('sessions')
    const presets = ctx.get('agentPresets')
    if (!sessions || !presets) return null
    const session = sessions.get(sid)
    if (!session) return null
    const pid = presets.presetForSession(session)
    if (pid) rememberSession(sid, pid)
    return pid || null
  } catch (e) { return null }
}

// ── 目标提取（P0-03：加 IPv6 字面量）──────────────────────────────
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g
// 候选切分放宽（含 :: 压缩与方括号形式），最终用 net.isIPv6 判定是否合法 IPv6
const IPV6_RE = /\[([0-9a-fA-F:]{2,45})\]|(?<![\w:])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![\w:])/g
const DOMAIN_RE = /(?<![a-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![a-z0-9-])/gi
const LOCAL_V4_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|255\.)/
const LOCAL_V6_RE = /^(::1|fe80:|fc|fd)/i

function extractTargets(obj, out = { domains: new Set(), ips: new Set(), v6: new Set() }, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return out
  if (typeof obj === 'string') {
    const s = obj
    for (const m of s.match(IPV4_RE) || []) out.ips.add(m)
    for (const m of s.matchAll(IPV6_RE)) {
      const cand = (m[1] || m[2] || '').toLowerCase()
      if (!cand.includes(':')) continue
      try { if (net.isIPv6(cand)) out.v6.add(cand) } catch (e) { /* not v6 */ }
    }
    for (const m of s.match(DOMAIN_RE) || []) {
      const d = m.toLowerCase()
      if (d.includes('.') && !/^\d+\./.test(d) && !/^[0-9a-f:]+$/.test(d)) out.domains.add(d)
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

/** 授权是否在有效期内（P0-03 问题 H：expires 必须真正参与判断） */
function authActive(sc, now = Date.now()) {
  const a = sc && sc.authorization
  if (a) {
    if (a.status && String(a.status).toLowerCase() !== 'active') return { ok: false, why: 'authorization.status=' + a.status }
    if (a.startsAt) {
      const t = Date.parse(a.startsAt)
      if (!isNaN(t) && now < t) return { ok: false, why: '授权尚未生效（startsAt=' + a.startsAt + '）' }
    }
    if (a.expiresAt) {
      const t = Date.parse(a.expiresAt)
      if (!isNaN(t) && now > t) return { ok: false, why: '授权已过期（expiresAt=' + a.expiresAt + '）' }
    }
  }
  return { ok: true }
}

/** 单条 target 是否仍在有效期（兼容旧的 targets.<名字>.expires） */
function targetExpired(t, now = Date.now()) {
  if (!t || !t.expires) return false
  const e = Date.parse(String(t.expires) + 'T23:59:59')
  return !isNaN(e) && now > e
}

/**
 * 越界判定（P0-03）。
 * @returns {{bad: Array, unverifiable: boolean}} unverifiable=true 表示无法判断（scope 坏了/缺失）
 */
function outOfScope(args, sc) {
  if (!sc || !sc.targets) return { bad: [], unverifiable: true }
  const { domains, ips, v6 } = extractTargets(args)
  const allowLocal = sc.allowLocal === true            // P0-03 问题 G：默认 **不** 放行内网
  const allowUnlisted = sc.allowUnlisted === true
  const now = Date.now()

  const tgt = sc.targets
  const targetDomains = []
  const targetIps = []
  const targetCidrs = []

  if (Array.isArray(tgt.domains)) targetDomains.push(...tgt.domains)
  if (Array.isArray(tgt.ips)) targetIps.push(...tgt.ips)
  if (Array.isArray(tgt.cidrs)) targetCidrs.push(...tgt.cidrs)
  // 兼容旧结构 targets.<名字>.{domains,ips,expires}
  for (const t of Object.values(tgt)) {
    if (!t || typeof t !== 'object') continue
    if (targetExpired(t, now)) continue          // 过期 target 不再提供授权
    for (const d of t.domains || []) targetDomains.push(d)
    for (const i of t.ips || []) targetIps.push(i)
  }
  const normDomains = targetDomains.map((x) => String(x).toLowerCase().replace(/\.$/, ''))
  const service = (sc.serviceAllowlist || sc.excludeDomains || []).map((x) => String(x).toLowerCase())

  const bad = []
  for (const d of domains) {
    if (normDomains.some((x) => d === x || d.endsWith('.' + x))) continue
    if (service.some((x) => d === x || d.endsWith('.' + x))) continue   // 辅助服务：允许访问，不等于授权测试
    if (allowUnlisted) continue
    bad.push({ kind: 'domain', value: d })
  }
  for (const ip of ips) {
    if (allowLocal && LOCAL_V4_RE.test(ip)) continue
    if (targetIps.includes(ip)) continue
    if (targetCidrs.some((c) => ipInCidr(ip, c))) continue
    if (allowUnlisted) continue
    bad.push({ kind: 'ip', value: ip })
  }
  for (const ip of v6) {
    if (allowLocal && LOCAL_V6_RE.test(ip)) continue
    if ((sc.targets.ipv6 || []).map(String).includes(ip)) continue
    if (allowUnlisted) continue
    bad.push({ kind: 'ipv6', value: ip })
  }
  return { bad, unverifiable: false }
}

// ── 参数校验（P1-01：递归 + 数字字符串）────────────────────────────
function findArgValues(obj, targetName, depth = 0, out = []) {
  if (depth > 5 || obj === null || obj === undefined) return out
  if (typeof obj !== 'object') return out
  if (Array.isArray(obj)) {
    for (const v of obj) findArgValues(v, targetName, depth + 1, out)
    return out
  }
  for (const [k, v] of Object.entries(obj)) {
    if (k === targetName) out.push(v)
    else if (v && typeof v === 'object') findArgValues(v, targetName, depth + 1, out)
  }
  return out
}

function toNumber(v) {
  if (typeof v === 'number') return v
  if (typeof v === 'string' && /^\s*-?\d+(\.\d+)?\s*$/.test(v)) return Number(v)
  return null
}

// ── 角色匹配（P0-04：边界匹配，不用裸 includes）─────────────────────
function presetMatchesKey(presetId, key) {
  if (!presetId || !key) return false
  const p = String(presetId).toLowerCase()
  const k = String(key).toLowerCase()
  if (p === k) return true
  // 边界匹配：避免 "recon" 命中 "reconx"
  return p.endsWith('-' + k) || p.startsWith(k + '-') || p.includes('-' + k + '-')
}

// ── 规则判定 ────────────────────────────────────────────────────────
/**
 * @returns {null|{rule, reason, matched?, via?, severity?}}
 */
function evaluate(exec, cfg, ctx) {
  const tool = String(exec && exec.name || '')
  const args = (exec && exec.arguments) || {}

  // ① 无条件工具拒绝
  if (cfg.toolDeny && Object.prototype.hasOwnProperty.call(cfg.toolDeny, tool)) {
    return { rule: 'toolDeny', reason: cfg.toolDeny[tool] || `工具 ${tool} 被策略禁止` }
  }

  // ② 角色权限（P0-04：allow 白名单优先于 deny 黑名单）
  const presetId = presetOfAgent(ctx, exec)
  if (cfg.agents && Object.keys(cfg.agents).length) {
    const key = Object.keys(cfg.agents).find((k) => presetMatchesKey(presetId, k))
    if (key) {
      const rule = cfg.agents[key] || {}
      const deny = Array.isArray(rule.deny) ? rule.deny : []
      const allow = Array.isArray(rule.allow) ? rule.allow : null
      if (allow) {
        // 白名单模式：不在 allow 里的一律拒绝
        if (!allow.includes(tool)) {
          return { rule: 'agentAllowlist', matched: key, reason: rule.reason || `角色 ${key} 未显式授权 ${tool}` }
        }
      } else if (deny.includes(tool)) {
        return { rule: 'agentDeny', matched: key, reason: rule.reason || `角色 ${key} 不允许调用 ${tool}` }
      }
    } else if (cfg.requireAgentIdentity === true) {
      // P0-04 要求 4：身份未知时默认拒绝（仅在显式开启时，避免误伤主会话）
      return { rule: 'agentUnknown', reason: `无法确认调用者角色（presetId=${presetId || 'null'}），按策略拒绝 ${tool}` }
    }
  }

  // ③ 参数上限（P1-01：递归 + 数字字符串）
  if (cfg.argMax) {
    for (const [argName, max] of Object.entries(cfg.argMax)) {
      const limit = toNumber(max)
      if (limit === null) continue
      for (const raw of findArgValues(args, argName)) {
        const v = toNumber(raw)
        if (v !== null && v > limit) {
          return { rule: 'argMax', matched: argName, reason: `参数 ${argName}=${raw} 超过上限 ${limit}（防一次拉全库）` }
        }
      }
    }
  }

  // ④ 工具+参数条件
  if (Array.isArray(cfg.argDeny)) {
    for (const r of cfg.argDeny) {
      if (!r || r.tool !== tool) continue
      const gt = toNumber(r.gt)
      if (gt === null) continue
      for (const raw of findArgValues(args, r.arg)) {
        const v = toNumber(raw)
        if (v !== null && v > gt) {
          return { rule: 'argDeny', matched: r.arg, reason: r.reason || `${tool}.${r.arg}=${raw} 超过 ${gt}` }
        }
      }
    }
  }

  // ⑤ 授权范围（P0-03）
  const { scope } = loadScope()
  if (scope) {
    const auth = authActive(scope)
    if (!auth.ok) {
      return { rule: 'scopeExpired', reason: auth.why }
    }
    const { bad, unverifiable } = outOfScope(args, scope)
    if (unverifiable) {
      return { rule: 'scopeUnavailable', reason: '授权范围文件不可用，无法证明目标在范围内' }
    }
    if (bad.length) {
      const what = bad.slice(0, 3).map((b) => b.value).join(', ')
      return { rule: 'outOfScope', matched: bad[0].value, reason: `目标不在授权范围内：${what}` }
    }
  }

  return null
}

// ── 安全状态计算（P0-01）────────────────────────────────────────────
function computeState(cfgInfo, scopeInfo) {
  const reasons = []
  if (cfgInfo && cfgInfo.broken) { reasons.push('策略文件不可用'); return { state: STATE.BLOCKED, reasons } }
  if (cfgInfo && cfgInfo.stale) reasons.push('策略文件有错误，正在使用上一份有效策略')
  if (scopeInfo && (scopeInfo.missing || scopeInfo.broken)) reasons.push('授权范围文件不可用')
  if (reasons.length) return { state: STATE.DEGRADED, reasons }
  return { state: STATE.NORMAL, reasons: [] }
}

function isProtected(tool, cfg) {
  const extra = Array.isArray(cfg && cfg.protectedTools) ? cfg.protectedTools : []
  return DEFAULT_PROTECTED.includes(tool) || extra.includes(tool) || /^redteam_/.test(tool)
}

// ── 插件主体 ────────────────────────────────────────────────────────
function apply(ctx) {
  try {
    const c = ctx && ctx.config
    if (c && typeof c.workspace === 'string' && c.workspace) WS = c.workspace
  } catch (e) { /* ignore */ }
  if (!WS) WS = defaultWs()

  const cfgInfo0 = loadCfg()
  const scopeInfo0 = loadScope()
  const st0 = computeState(cfgInfo0, scopeInfo0)
  const cfg0 = cfgInfo0.cfg
  const observing = String(cfg0.mode || '').toLowerCase() !== 'enforce'

  // P0-02：启动时必须明确「是否真的会拦」，不允许让人误以为已生效
  try {
    const bar = '='.repeat(64)
    const lines = [
      '',
      bar,
      ' Tool Guardrail Status',
      bar,
      ' Plugin Loaded  : YES  (v1.1.0, pid ' + PID + ', profile ' + PROFILE + ')',
      ' Policy Loaded  : ' + (cfgInfo0.broken ? 'BROKEN' : 'YES') + '  (' + policyPath() + ')',
      ' Scope Loaded   : ' + (scopeInfo0.missing ? 'MISSING' : scopeInfo0.broken ? 'BROKEN' : 'YES'),
      ' Agent Mapping  : ' + (PRESET_BY_SESSION.size ? 'READY' : 'WAITING (agent/created 后建立)'),
      ' Security State : ' + st0.state + (st0.reasons.length ? '  ← ' + st0.reasons.join('; ') : ''),
      ' Current Mode   : ' + String(cfg0.mode || 'observe').toUpperCase(),
      ' Blocking       : ' + (observing ? 'NO' : 'YES'),
      observing
        ? ' WARNING: 违规工具调用【不会】被拦截，只记录。要真正拦截请把 mode 改成 enforce。'
        : ' Blocking is ENABLED.',
      bar,
      '',
    ]
    process.stderr.write(lines.join('\n') + '\n')
  } catch (e) { /* 状态打印失败不影响主流程 */ }

  enqueue(cfg0.probeLog, {
    t: Date.now(), tag: 'plugin-loaded', version: '1.1.0',
    profile: PROFILE, pid: PID, workspace: WS,
    policyExists: fs.existsSync(policyPath()),
    scopeExists: fs.existsSync(scopePath()),
    mode: cfg0.mode, enabled: cfg0.enabled,
    securityState: st0.state, reasons: st0.reasons,
    blocking: !observing,
  })

  // 服务自检
  try {
    const probe = { t: Date.now(), tag: 'services-probe' }
    for (const svc of ['tools', 'sessions', 'agents', 'agentPresets', 'systemPrompt', 'redteam']) {
      let ok = false
      try { ok = !!(ctx && typeof ctx.get === 'function' && ctx.get(svc)) } catch (e) { ok = false }
      probe[svc] = ok
    }
    probe.guardAvailable = !!(ctx && ctx.tools && typeof ctx.tools.guard === 'function')
    probe.presetChain = !!(probe.sessions && probe.agentPresets)
    enqueue(cfg0.probeLog, probe)
  } catch (e) { /* ignore */ }

  // agent/created：建 sessionId → presetId 映射（唯一可靠途径，见文件头说明）
  try {
    ctx.on('agent/created', ({ agent } = {}) => {
      try {
        if (!agent || !agent.id) return
        let pid = null
        try { pid = agent.ctx?.get('agentPresets')?.composedPreset(agent.ctx) ?? null } catch (e) { pid = null }
        if (pid) rememberSession(agent.id, pid)
        enqueue(cfg0.probeLog, {
          t: Date.now(), tag: 'agent-created',
          sessionId: agent.id, presetId: pid, hasCtx: !!agent.ctx,
        })
      } catch (e) {
        enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-failed', error: String(e && e.message) })
      }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'agent-created-register-failed', error: String(e && e.message) })
  }

  // 定期清理过期 session（P1-04）
  try {
    const t = setInterval(() => { try { sweepSessions() } catch (e) { /* ignore */ } }, 10 * 60 * 1000)
    if (t && typeof t.unref === 'function') t.unref()
  } catch (e) { /* ignore */ }

  // ── 核心：pre-execute 拦截（实测唯一生效的钩子）──────────────────
  try {
    ctx.on('tools/pre-execute', async (exec, next) => {
      const tool = String((exec && exec.name) || '')
      const cfgInfo = loadCfg()
      const scopeInfo = loadScope()
      const cfg = cfgInfo.cfg
      const { state, reasons } = computeState(cfgInfo, scopeInfo)
      const enforcing = String(cfg.mode || '').toLowerCase() === 'enforce'
      const protectedTool = isProtected(tool, cfg)

      try {
        if (!cfg.enabled) return next()

        const presetId = presetOfAgent(ctx, exec)
        let verdict = null
        let internal = null

        try {
          verdict = evaluate(exec, cfg, ctx)
        } catch (e) {
          internal = String(e && e.message)
        }

        // P0-01：内部异常时不再无条件放行。
        //   受保护工具 + enforce → 拒绝；普通工具 → 放行但必须留痕。
        if (internal) {
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, callId: exec && exec.callId,
            phase: 'pre-execute', decision: protectedTool && enforcing ? 'deny' : 'error-pass',
            rule: 'internalError', reason: '护栏内部异常: ' + internal,
            presetId, argsHash: argsHash(exec && exec.arguments),
          })
          if (protectedTool && enforcing) {
            return { kind: 'deny', reason: '[guardrail] 护栏内部异常，拒绝受保护工具 ' + tool + '（' + internal + '）',
              info: { name: 'GuardrailInternalError', code: 'GUARDRAIL_INTERNAL' } }
          }
          return next()
        }

        // BLOCKED 状态（策略文件坏了）：只拦受保护工具
        if (state === STATE.BLOCKED && protectedTool && enforcing) {
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, phase: 'pre-execute', decision: 'deny',
            rule: 'stateBlocked', reason: reasons.join('; '), presetId,
          })
          return { kind: 'deny', reason: '[guardrail] 安全策略不可用（' + reasons.join('; ') + '），拒绝受保护工具 ' + tool,
            info: { name: 'GuardrailBlocked', code: 'GUARDRAIL_BLOCKED' } }
        }

        // 无条件诊断（保留 v0.8.1 的可观测性）
        try {
          enqueue(cfg.probeLog, {
            t: Date.now(), tag: 'pre-execute-seen', tool,
            agentId: exec && exec.agent && exec.agent.id ? String(exec.agent.id).slice(0, 40) : null,
            presetId, mapSize: PRESET_BY_SESSION.size,
            agentsKeys: cfg.agents ? Object.keys(cfg.agents) : [],
            deniedByRule: verdict ? verdict.rule : null,
            outcome: verdict ? (enforcing ? 'deny' : 'would-deny') : 'pass',
            securityState: state,
          })
        } catch (e) { /* ignore */ }

        if (verdict) {
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, callId: exec && exec.callId,
            phase: 'pre-execute',
            decision: enforcing ? 'deny' : 'would-deny',
            rule: verdict.rule, matched: verdict.matched, reason: verdict.reason,
            presetId, argsHash: argsHash(exec && exec.arguments),
            policyVersion: cfg.policyVersion,
          })
          if (enforcing) {
            return {
              kind: 'deny',
              reason: '[guardrail] ' + verdict.reason + '（规则 ' + verdict.rule +
                (verdict.matched ? ':' + verdict.matched : '') + '）',
              info: { name: 'GuardrailDenied', code: 'GUARDRAIL_DENIED' },
            }
          }
          return next()
        }

        // 审批（按工具名；更细的风险判定留待 DSH 暴露审批结果事件后再做）
        const ap = cfg.approval || {}
        const needAsk = Array.isArray(ap.tools) && ap.tools.includes(tool)
        if (needAsk && enforcing) {
          const id = 'APR-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6)
          // 存参数摘要，approval/request 里用 callId 关联回来（那边拿不到 arguments）
          try {
            if (exec && exec.callId) {
              const tg = extractTargets(exec.arguments || {})
              PENDING_APPROVAL.set(exec.callId, {
                argsHash: argsHash(exec.arguments),
                target: [...tg.domains].slice(0, 3).join(',') || [...tg.ips].slice(0, 3).join(',') || null,
                presetId, at: Date.now(),
              })
            }
          } catch (e) { /* ignore */ }
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, callId: exec && exec.callId, approvalId: id,
            phase: 'pre-execute', decision: 'ask', rule: 'approval',
            reason: ap.reason || '高危动作需人工确认',
            presetId, argsHash: argsHash(exec && exec.arguments),
          })
          return {
            kind: 'ask',
            reason: '[guardrail] ' + (ap.reason || '该动作被列为需人工确认') + '：' + tool,
            displayReason: { en: 'Guardrail approval required: ' + tool, zh: '护栏要求人工确认：' + tool },
          }
        }
        return next()
      } catch (e) {
        // 最后一道：连判定框架都挂了。受保护工具 + enforce 时拒绝。
        try {
          enqueue(cfg.auditLog, {
            t: Date.now(), tool, phase: 'pre-execute',
            decision: 'error-deny', rule: 'frameworkError', reason: String(e && e.message),
          })
        } catch (e2) { /* ignore */ }
        if (isProtected(tool, loadCfg().cfg) && String(loadCfg().cfg.mode || '').toLowerCase() === 'enforce') {
          return { kind: 'deny', reason: '[guardrail] 护栏框架异常，拒绝受保护工具 ' + tool,
            info: { name: 'GuardrailFrameworkError', code: 'GUARDRAIL_FRAMEWORK' } }
        }
        return next()
      }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'pre-execute-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'pre-execute-failed', error: String(e && e.message) })
  }

  // ── 审批闭环（P1-02）──────────────────────────────────────────────
  // DSH 的 `approval/request` 是 waterfall，返回 ApprovalOutcome：
  //   'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'
  // 参数只有 { agent, toolName, callId, reason, displayReason, signal } —— **没有 arguments**，
  // 所以参数哈希要在 pre-execute 返回 ask 时先存下来，再用 callId 关联。
  // 注意 `allowed-once` 是 DSH 自己的语义：审批只生效一次，天然满足"审批不能重复使用"。
  try {
    ctx.on('approval/request', async (req, next) => {
      const tool = String((req && req.toolName) || '')
      const callId = req && req.callId
      const agentId = req && req.agent && req.agent.id
      const approvalId = 'APR-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6)
      const pending = callId ? PENDING_APPROVAL.get(callId) : undefined
      const cfg = loadCfg().cfg

      enqueue(cfg.auditLog, {
        t: Date.now(), phase: 'approval', decision: 'pending',
        approvalId, tool, callId, agentId: agentId ? String(agentId).slice(0, 40) : null,
        presetId: lookupPreset(agentId) || (pending && pending.presetId) || null,
        argsHash: pending ? pending.argsHash : null,
        target: pending ? pending.target : null,
        reason: req && req.reason || null,
        requestedAt: new Date().toISOString(),
      })

      let outcome = 'unavailable'
      let err = null
      try {
        outcome = await next()          // 交给下游（DSH 的审批 UI）
      } catch (e) {
        err = String(e && e.message)
        // 审批链自己出错 → 按 fail-closed 处理（P0-01 要求）
        outcome = 'unavailable'
      }

      enqueue(cfg.auditLog, {
        t: Date.now(), phase: 'approval', decision: outcome,
        approvalId, tool, callId,
        agentId: agentId ? String(agentId).slice(0, 40) : null,
        presetId: lookupPreset(agentId) || (pending && pending.presetId) || null,
        argsHash: pending ? pending.argsHash : null,
        target: pending ? pending.target : null,
        executed: outcome === 'allowed-once',
        decidedAt: new Date().toISOString(),
        error: err,
      })
      if (callId) PENDING_APPROVAL.delete(callId)   // 一次性：配对完就清
      enqueue(cfg.probeLog, { t: Date.now(), tag: 'approval-decided', approvalId, tool, outcome })
      return outcome
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'approval-hook-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'approval-hook-failed', error: String(e && e.message) })
  }

  // 结果观察（审计：只记结论，不记参数）
  try {
    ctx.on('tools/result', (exec, result) => {
      try {
        const cfg = loadCfg().cfg
        enqueue(cfg.auditLog, {
          t: Date.now(), tool: exec && exec.name, callId: exec && exec.callId,
          isError: !!(result && result.isError), phase: 'result',
        })
      } catch (e) { /* ignore */ }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-failed', error: String(e && e.message) })
  }
}

export { name, inject, apply, evaluate, loadCfg, loadScope, outOfScope, redactValue, presetMatchesKey, flush as flushLogs }
