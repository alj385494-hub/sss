/**
 * dsh-tool-guardrail v2.1.2 —— 工具护栏
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
 * v2.1.2 相对 v0.8.2 的变更（对应第二轮审计 P0/P1）：
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
import path from 'node:path'
import os from 'node:os'

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
// 2026-11-19 实测发现的严重问题：DSH 里 process.cwd() = ~/.dsh/profiles/desktop，
// 那里**没有** runs/tools/，于是 defaultWs() 的探测循环全落空、返回 profile 目录，
// 结果 policy/scope 全读不到 → 插件一直拿 DEFAULT_CFG 在跑（配置形同虚设）。
// 指针文件：~/.dsh/profiles/<profile>/runs/ws-pointer.txt 写一行工作区绝对路径。
function readWsPointer() {
  const bases = []
  try { bases.push(process.cwd()) } catch (e) {}
  try { bases.push(path.join(os.homedir(), '.dsh', 'profiles')) } catch (e) {}
  for (const b of bases) {
    try {
      const p = path.join(b, 'runs', 'ws-pointer.txt')
      if (!fs.existsSync(p)) continue
      const raw = fs.readFileSync(p, 'utf8')
      const v = raw.split(String.fromCharCode(10)).map((x) => x.trim()).filter(Boolean)[0] || ''
      if (v && fs.existsSync(path.join(v, 'runs', 'tools'))) return v
    } catch (e) { /* next */ }
  }
  return null
}

function defaultWs() {
  const cands = [
    process.env.GUARDRAIL_WS,
    process.env.DSH_WORKSPACE,
    readWsPointer(),
    process.cwd(),
    // 不再硬编码某个人的工作区：靠 ctx.config.workspace / 环境变量 / cwd 自适应。
    // （原来这里写了绝对路径，导致插件主文件被报"含本机路径"）
  ].filter(Boolean)
  for (const c of cands) {
    try { if (fs.existsSync(c + '/runs/tools')) return c } catch (e) { /* next */ }
  }
  return process.cwd()
}
const POLICY_FILE = '/runs/tools/guardrail-policy.json'
const SCOPE_FILE = '/runs/tools/scope.json'
function setWorkspace(p) { if (typeof p === 'string' && p) WS = p }

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

// ── C13-14：脱敏规则 ────────────────────────────────────────────────
// 旧实现只按固定字段名匹配，漏掉 x-api-key / client-secret / customCredential 等写法，
// 也完全不认自由文本里的长凭据。
const SECRET_KEY_RE = /^(x[-_]?api[-_]?key|api[-_]?key|apikey|access[-_]?token|refresh[-_]?token|auth[-_]?token|id[-_]?token|bearer|authorization|client[-_]?secret|clientsecret|customcredential|secret|password|passwd|pwd|token|session|sessionid|session[-_]?key|jwt|credential[s]?|private[-_]?key|ssh[-_]?key|secret[-_]?key|cookie|set[-_]?cookie|proxy[-_]?authorization)$/i

// 未知长凭据：长度 ≥32、无空白、字符种类 ≥3（或 JWT / PEM 头）。
// 目的是兜住"字段名不认识但明显是密钥"的情况。
function looksLikeSecret(v) {
  if (typeof v !== 'string') return false
  const s = v.trim()
  // PEM / JWT 先判（PEM 是多行，含空白，不能先被下面的空白检查排除）
  if (/^-----BEGIN [A-Z ]+-----/.test(s)) return true
  if (/^(eyJ[A-Za-z0-9_-]+\.){1,2}/.test(s) && !/\s/.test(s)) return true
  if (s.length < 32 || /\s/.test(s)) return false
  // URL 不算凭据（否则整个 URL 会被替掉，审计里就看不到打了哪个地址）
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return false
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(s)).length
  return kinds >= 3
}

// URL 查询参数里的敏感值：?token=...&api_key=...
function redactUrlQuery(u) {
  try {
    return String(u).replace(/([?&])([^=&#]+)=([^&#]*)/g, (m, sep, k, v) => {
      if (SECRET_KEY_RE.test(decodeURIComponent(k)) || looksLikeSecret(decodeURIComponent(v))) {
        return sep + k + '=[REDACTED]'
      }
      return m
    })
  } catch (e) { return u }
}

// Bearer / Basic 头里的凭据
function redactAuthText(t) {
  try {
    return String(t)
      .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]{12,}=*/gi, '$1[REDACTED]')
      .replace(/(Basic\s+)[A-Za-z0-9+/=]{12,}/gi, '$1[REDACTED]')
  } catch (e) { return t }
}

function redactValue(v, depth = 0) {
  // C13-14：先处理自由文本里的 Bearer/Basic 与 URL 查询参数
  if (typeof v === "string") {
    let t = redactAuthText(v)
    if (/[?&][^=&#]+=/.test(t)) t = redactUrlQuery(t)
    v = t
  }

  if (v === null || v === undefined) return v
  if (depth > 6) return '[deep]'
  if (typeof v === 'string') {
    if (v.length > 400) return v.slice(0, 400) + '…[truncated ' + v.length + ']'
    // 整个字符串就是一个长凭据（JWT / PEM / 高熵串）
    if (looksLikeSecret(v)) return REDACT
    let s = v
    for (const re of SENSITIVE_INLINE) s = s.replace(re, (m, p1) => p1 + REDACT)
    return s
  }
  if (typeof v !== 'object') return v
  if (Array.isArray(v)) return v.slice(0, 20).map((x) => looksLikeSecret(x) ? REDACT : redactValue(x, depth + 1))
  const out = {}
  let k = 0
  for (const key of Object.keys(v)) {
    if (k++ > 40) { out['…'] = 'truncated'; break }
    // C13-14：字段名用 SECRET_KEY_RE（覆盖 x-api-key / client-secret / customCredential 等写法），
    // 值用 looksLikeSecret 兜住"字段名不认识但明显是密钥"的情况。
    const isSecretKey = SENSITIVE_KEY.test(key) || SECRET_KEY_RE.test(key)
    const rawVal = v[key]
    out[key] = (isSecretKey || looksLikeSecret(rawVal)) ? REDACT : redactValue(rawVal, depth + 1)
  }
  return out
}
// G-21：完整 SHA-256（64 hex），且基于**未脱敏的规范化参数**计算。
// 旧实现有三处问题：只取前 16 hex（64bit）；基于脱敏后的内容；key 顺序不稳定。
// 脱敏后的内容会把不同的 password 都变成 [REDACTED] → 不同参数得到相同哈希。
// C13-21：规范化版本。改语义时必须递增，审计里带出来才能解释历史哈希。
const CANON_VERSION = 1
const CANON_MAX_DEPTH = 64
const CANON_MAX_LEN = 1 << 20   // 1 MiB，超过就判不可验证

function canonicalize(v, depth = 0) {
  if (v === null || v === undefined) return "null"
  // C13-21：旧实现 depth>8 返回 "[deep]"，导致**两个不同的深层参数得到同一个哈希**。
  // 现在超深一律返回 null，由 argsHash 判为"不可验证"，不静默压缩。
  if (depth > CANON_MAX_DEPTH) return null
  const t = typeof v
  if (t === "number") return Number.isFinite(v) ? String(v) : "null"
  if (t === "boolean") return v ? "true" : "false"
  if (t === "string") return JSON.stringify(v)
  if (Array.isArray(v)) {
    const parts = v.map((x) => canonicalize(x, depth + 1))
    if (parts.some((x) => x === null)) return null
    return "[" + parts.join(",") + "]"
  }
  if (t === "object") {
    const keys = Object.keys(v).sort()
    const parts = keys.map((k) => {
      const c = canonicalize(v[k], depth + 1)
      return c === null ? null : JSON.stringify(k) + ":" + c
    })
    if (parts.some((x) => x === null)) return null
    return "{" + parts.join(",") + "}"
  }
  return "null"
}

function argsHash(args) {
  try {
    const norm = canonicalize(args)
    // C13-21：规范化失败（超深/超长）时返回 null = 不可验证，调用方据此拒绝或标记
    if (norm === null || norm === undefined) return null
    if (norm.length > CANON_MAX_LEN) return null
    return "sha256:" + crypto.createHash("sha256").update(norm, "utf8").digest("hex")
  } catch (e) { return null }
}

// C13-21：审计里除了 argsHash 还要带算法与规范化版本，否则历史哈希无法解释。
// 注：如需防"日志泄露后离线枚举参数"，应改 HMAC-SHA-256 + 独立密钥；
// 本实现未做 HMAC（密钥管理成本高），审计字段 hashAlgorithm 会如实写成 sha256。
function hashMeta() {
  return { hashAlgorithm: 'sha256', canonicalizationVersion: CANON_VERSION }
}

// ── 日志（P1-03：队列上限 + 写失败告警 + 退出 flush）────────────────
const QUEUE_MAX = 2000
let _q = []
let _flushing = false
let _writeFailures = 0
let _dropped = 0

// G-19：安全审计（auditLog）不允许静默丢弃。溢出时置 AUDIT_OVERFLOW，
// enforce 下由 pre-execute 拒绝受保护工具；诊断日志（probeLog）仍可按策略丢弃。
let AUDIT_OVERFLOW = false
let _droppedAudit = 0   // C13-03：重试耗尽被丢弃的安全审计条数

// C13-09：日志路径必须规范化并校验在工作区内。
// 旧实现 `WS + "/" + it.file.replace(/^\/+/, "")` 没做任何规范化，
// 策略里写 auditLog: "../../evil.jsonl" 就能写到工作区外面去。
// C13-24：日志里不记完整工作区绝对路径（含用户名等本机信息）。
// 只记「末段目录名 + 路径哈希前 8 位」—— 既能在多工作区时区分，又不泄露结构。
// 需要完整路径时用环境变量 GUARDRAIL_DEBUG_WS=1 打开（调试用）。
function wsLabel(p) {
  if (!p) return null
  if (process.env.GUARDRAIL_DEBUG_WS === '1') return p
  try {
    const base = path.basename(String(p).replace(/[\/]+$/, "")) || "(root)"
    const h = crypto.createHash('sha256').update(String(p)).digest('hex').slice(0, 8)
    return base + '#' + h
  } catch (e) { return '(unresolved)' }
}


function safeLogPath(file) {
  if (typeof file !== 'string' || !file) return null
  const base = path.resolve(WS)
  let abs
  try {
    abs = path.resolve(base, file)
  } catch (e) {
    return null
  }
  // 必须落在工作区内（区分大小写由平台决定，这里只在 Windows 下不区分）
  const sameOrChild = (a, b) => a === b || a.startsWith(b + path.sep)
  const norm = (x) => (process.platform === 'win32' ? x.toLowerCase() : x)
  if (!sameOrChild(norm(abs), norm(base))) return null
  // 拒绝符号链接（防止通过链接跳出工作区）
  try {
    const st = fs.lstatSync(abs)
    if (st.isSymbolicLink()) return null
  } catch (e) { /* 不存在 = 正常，稍后会创建 */ }
  return abs
}

// C13-08：严格的执行结果判定。
// 旧实现  在 result 为 null/结构异常时
// 得到 false，于是记成 execution_succeeded —— 没收到结果也当成功。
function judgeExecution(result) {
  if (result === undefined || result === null) return 'execution_unknown'
  if (typeof result !== 'object') return 'execution_unknown'
  if (result.isError === true) return 'execution_failed'
  if (result.isError === false) return 'execution_succeeded'
  if (result.cancelled === true) return 'execution_cancelled'
  if (result.timeout === true) return 'execution_timeout'
  return 'execution_unknown'
}


function enqueue(file, obj) {
  const auditFile = ((_cfg && _cfg.auditLog) || DEFAULT_CFG.auditLog)
  const isAudit = file === auditFile
  if (_q.length >= QUEUE_MAX) {
    _dropped += 1
    if (isAudit) {
      if (!AUDIT_OVERFLOW) {
        AUDIT_OVERFLOW = true
        process.stderr.write('[guardrail] FATAL 安全审计队列溢出，审计事件开始丢失；'
          + 'enforce 下将拒绝受保护工具' + String.fromCharCode(10))
      }
    }
    if (_dropped === 1 || _dropped % 100 === 0) {
      process.stderr.write('[guardrail] WARN 日志队列已满，累计丢弃 ' + _dropped + ' 条'
        + (isAudit ? '（含安全审计）' : '（诊断）') + String.fromCharCode(10))
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

// G-05：写失败的条目必须退回队列重试，不能静默丢弃。
// 连续失败超过阈值 -> AUDIT_BROKEN，enforce 下拒绝受保护工具。
let AUDIT_BROKEN = false
const RETRY_MAX = 5

function flush() {
  if (_q.length === 0) return
  const batch = _q
  _q = []
  const failed = []
  for (const it of batch) {
    // C13-09：路径规范化 + 工作区边界校验（越界一律拒绝，不写）
    const p = safeLogPath(it.file)
    if (!p) {
      if (_blockedLogPath++ < 3) {
        process.stderr.write("[guardrail] ERROR 审计路径越界，已拒绝写入: " + it.file + String.fromCharCode(10))
      }
      _droppedAudit += 1
      AUDIT_BROKEN = true
      continue
    }
    try {
      fs.appendFileSync(p, it.line + String.fromCharCode(10), "utf8")
      _writeFailures = 0
    } catch (e) {
      _writeFailures += 1
      it.retries = (it.retries || 0) + 1
      if (it.retries <= RETRY_MAX) {
        failed.push(it)
      } else {
        // C13-03：重试耗尽 = 这条安全审计**永久丢失**。必须计数并立刻置 AUDIT_BROKEN，
        // 旧实现把它悄悄丢掉，然后因为 failed 为空把 AUDIT_BROKEN 又重置成 false。
        _droppedAudit += 1
        AUDIT_BROKEN = true
        if (_droppedAudit === 1 || _droppedAudit % 20 === 0) {
          process.stderr.write("[guardrail] FATAL 安全审计已丢失 " + _droppedAudit +
            " 条（重试 " + RETRY_MAX + " 次仍写不进），enforce 下拒绝受保护工具" + String.fromCharCode(10))
        }
      }
      if (_writeFailures <= 3 || _writeFailures % 50 === 0) {
        process.stderr.write("[guardrail] ERROR 审计日志写入失败(" + String(e && e.message) +
          ")，连续 " + _writeFailures + " 次，重试 " + it.retries + "/" + RETRY_MAX + String.fromCharCode(10))
      }
    }
  }
  if (failed.length) {
    _q = failed.concat(_q)
    if (_q.length > QUEUE_MAX) _q = _q.slice(0, QUEUE_MAX)
    if (_writeFailures > 20 && !AUDIT_BROKEN) {
      AUDIT_BROKEN = true
      process.stderr.write("[guardrail] FATAL 审计不可用：连续失败 " + _writeFailures +
        " 次，enforce 下将拒绝受保护工具" + String.fromCharCode(10))
    }
  }
  // 只有"本轮全部写成功 且 从未丢过审计"才解除 AUDIT_BROKEN。
  // 旧实现在 failed 为空时无条件重置，导致"全丢光了反而显示正常"。
  if (!failed.length && _writeFailures === 0 && _droppedAudit === 0) AUDIT_BROKEN = false
}

// 进程退出时尽力 flush
// G-20：**不接管** SIGINT / SIGTERM。
// 理由：给 SIGINT/SIGTERM 注册 listener 会让 Node 不再执行默认终止行为，
// 如果监听器只 flush 而不主动退出，进程就会挂住（这正是审计指出的问题）。
// DSH 是 Electron 应用，信号退出不是主路径；`exit` 事件足以做同步 flush。
// 明确行为：DSH 正常退出 -> 触发 exit -> 同步 flush（Node 允许 exit 里跑同步代码）。
//           进程被强杀 -> 丢最后未 flush 的条目（已在 AUDIT_BROKEN 机制里体现）。
try {
  process.on('exit', () => { try { flush() } catch (e) { /* last resort */ } })
} catch (e) { /* ignore */ }

// G-23：策略 Schema 校验。JSON 能 parse 不代表策略有效。
// 只做"能挡住明显错误"的检查，不追求覆盖 JSON Schema 全部语义。
function validatePolicySchema(o) {
  const errs = []
  if (!o || typeof o !== "object" || Array.isArray(o)) return ["顶层不是对象"]
  if (o.enabled !== undefined && typeof o.enabled !== "boolean") errs.push("enabled 必须是布尔")
  if (o.mode !== undefined && !["observe", "enforce"].includes(String(o.mode).toLowerCase())) {
    errs.push("mode 必须是 observe|enforce，实际 " + JSON.stringify(o.mode))
  }
  if (o.agents !== undefined) {
    if (!o.agents || typeof o.agents !== "object" || Array.isArray(o.agents)) {
      errs.push("agents 必须是对象")
    } else {
      for (const [k, v] of Object.entries(o.agents)) {
        if (!v || typeof v !== "object") { errs.push("agents." + k + " 必须是对象"); continue }
        for (const f of ["allow", "deny"]) {
          if (v[f] !== undefined && (!Array.isArray(v[f]) || v[f].some((x) => typeof x !== "string"))) {
            errs.push("agents." + k + "." + f + " 必须是字符串数组")
          }
        }
      }
    }
  }
  if (o.argMax !== undefined) {
    if (!o.argMax || typeof o.argMax !== "object" || Array.isArray(o.argMax)) errs.push("argMax 必须是对象")
    else for (const [k, v] of Object.entries(o.argMax)) {
      if (typeof v !== "number" || !Number.isFinite(v)) errs.push("argMax." + k + " 必须是数字")
    }
  }
  if (o.argDeny !== undefined) {
    if (!Array.isArray(o.argDeny)) errs.push("argDeny 必须是数组")
    else o.argDeny.forEach((r, i) => {
      if (!r || typeof r !== "object") errs.push("argDeny[" + i + "] 必须是对象")
      else {
        if (typeof r.tool !== "string") errs.push("argDeny[" + i + "].tool 必须是字符串")
        if (typeof r.arg !== "string") errs.push("argDeny[" + i + "].arg 必须是字符串")
      }
    })
  }
  if (o.approval !== undefined) {
    if (!o.approval || typeof o.approval !== "object") errs.push("approval 必须是对象")
    else if (o.approval.tools !== undefined && !Array.isArray(o.approval.tools)) {
      errs.push("approval.tools 必须是数组")
    }
  }
  if (o.toolDeny !== undefined && (typeof o.toolDeny !== "object" || Array.isArray(o.toolDeny))) {
    errs.push("toolDeny 必须是对象")
  }
  if (o.protectedTools !== undefined && !Array.isArray(o.protectedTools)) {
    errs.push("protectedTools 必须是数组")
  }
  // C13-22：以下为加强项 —— 旧实现只查类型，不查结构、长度、范围、未知字段
  const STR_MAX = 200
  const checkStr = (v, label, errs) => {
    if (typeof v !== 'string') { errs.push(label + ' 必须是字符串'); return }
    if (v.length > STR_MAX) errs.push(label + ' 超过 ' + STR_MAX + ' 字符')
  }
  // approval 结构
  if (o.approval !== undefined) {
    if (!o.approval || typeof o.approval !== 'object' || Array.isArray(o.approval)) {
      errs.push('approval 必须是对象')
    } else {
      if (o.approval.tools !== undefined) {
        if (!Array.isArray(o.approval.tools)) errs.push('approval.tools 必须是数组')
        else o.approval.tools.forEach((t, i) => checkStr(t, 'approval.tools[' + i + ']', errs))
      }
      if (o.approval.reason !== undefined) checkStr(o.approval.reason, 'approval.reason', errs)
    }
  }
  // protectedTools 元素
  if (Array.isArray(o.protectedTools)) {
    o.protectedTools.forEach((t, i) => checkStr(t, 'protectedTools[' + i + ']', errs))
  }
  // argDeny 元素：tool/arg 都是短字符串，可以带 pattern
  if (Array.isArray(o.argDeny)) {
    o.argDeny.forEach((r, i) => {
      if (!r || typeof r !== 'object') return
      checkStr(r.tool, 'argDeny[' + i + '].tool', errs)
      checkStr(r.arg, 'argDeny[' + i + '].arg', errs)
      if (r.pattern !== undefined) checkStr(r.pattern, 'argDeny[' + i + '].pattern', errs)
    })
  }
  // toolDeny 的值是"拒绝理由"，限长
  if (o.toolDeny && typeof o.toolDeny === 'object' && !Array.isArray(o.toolDeny)) {
    for (const [k, v] of Object.entries(o.toolDeny)) {
      checkStr(k, 'toolDeny 的键', errs)
      checkStr(v, 'toolDeny[' + k + ']', errs)
    }
  }
  // argMax 数值范围：上限不能是负数或天文数字
  if (o.argMax && typeof o.argMax === 'object' && !Array.isArray(o.argMax)) {
    for (const [k, v] of Object.entries(o.argMax)) {
      if (typeof v === 'number' && (v < 0 || v > 1e9)) errs.push('argMax.' + k + ' 超出合理范围 [0, 1e9]')
    }
  }
  // 未知顶层字段：明确拒绝拼错（比如把 approval 写成 aproval）
  const KNOWN = new Set(['enabled', 'mode', 'policyVersion', 'agents', 'toolDeny', 'argMax', 'argDeny',
    'approval', 'protectedTools', 'requireAgentIdentity', 'auditLog', 'probeLog', 'probeMax', 'reason', 'notes'])
  for (const k of Object.keys(o)) {
    // 以 $ 开头的是「JSON 没有注释」时的约定写法（ /  /  …），
    // 是人看的说明，不是配置项，不能当拼错拒绝。
    if (k.startsWith('$')) continue
    // 未知字段只**警告**不拒绝：加一个新字段就整份策略失效的代价太大，
    // 而拼错的风险可以由启动告警兜住。真正的结构错误（类型/范围/长度）才进 errs。
    if (!KNOWN.has(k)) {
      try { process.stderr.write('[guardrail] WARN 策略里有未知字段 "' + k + '"（忽略；拼错了？）' + String.fromCharCode(10)) } catch (e) {}
    }
  }

  return errs
}


// G-24：Policy 与 Scope 的一致性快照。
// 两者分别热加载，可能出现"policy 已更新、scope 还是旧的"这种不一致。
// 这里把两份内容的 hash 合成一个快照 id，写进每条审计；变化时单独记一条 policy-reload。
let _snapshotId = null

function currentSnapshot() {
  const p = loadCfg()
  const sc = loadScope()
  const ph = _cfgHash ? _cfgHash.slice(0, 8) : "none"
  const sh = _scopeHash ? _scopeHash.slice(0, 8) : "none"
  // C13-23：除内容哈希外，还要带两边的 Schema 版本 —— 否则无法判断"同一份内容在不同版本下语义是否相同"
  return { id: ph + "-" + sh, policyHash: ph, scopeHash: sh,
    policySchemaVersion: (p.cfg && p.cfg.policyVersion) || 'unset',
    scopeSchemaVersion: (sc.scope && sc.scope.version) || 'unset',
    policyError: p.error || null, scopeError: sc.error || null }
}

function noteSnapshot(cfg) {
  try {
    const snap = currentSnapshot()
    if (snap.id !== _snapshotId) {
      const prev = _snapshotId
      _snapshotId = snap.id
      enqueue(cfg.auditLog, {
        t: Date.now(), phase: "policy-reload", snapshotId: snap.id,
                policyHash: snap.policyHash, scopeHash: snap.scopeHash,
        policySchemaVersion: snap.policySchemaVersion, scopeSchemaVersion: snap.scopeSchemaVersion,
        policyError: snap.policyError, scopeError: snap.scopeError,
      })
    }
  } catch (e) { /* ignore */ }
}


// G-25：启动预检。不能因为"插件加载成功"就认定整个护栏正常。
function preflight() {
  const cfgInfo = loadCfg()
  const scopeInfo = loadScope()
  let pkgVersion = "unknown"
  try {
    const pkgPath = new URL("./package.json", import.meta.url)
    pkgVersion = JSON.parse(fs.readFileSync(pkgPath, "utf8")).version || "unknown"
  } catch (e) { pkgVersion = "unknown" }
  const checks = []
  checks.push(["node", process.versions.node, true])
  checks.push(["plugin", "1.5.0", true])
  checks.push(["policy", cfgInfo.broken ? "BROKEN" : "OK", !cfgInfo.broken])
  checks.push(["policySchema", cfgInfo.error ? "ERR" : "OK", !cfgInfo.error])
  checks.push(["scope", scopeInfo.missing ? "MISSING" : scopeInfo.broken ? "BROKEN" : "OK",
    !(scopeInfo.missing || scopeInfo.broken)])
  checks.push(["policyVersion", (cfgInfo.cfg && cfgInfo.cfg.policyVersion) || "unset", true])
  checks.push(["scopeVersion", (scopeInfo.scope && scopeInfo.scope.version) || "unset", true])
  return { pkgVersion, checks }
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
    // G-23：解析成功后再做 Schema 校验；不通过就当坏策略处理（不用不安全默认）
    const schemaErrs = validatePolicySchema(parsed)
    if (schemaErrs.length) {
      const msg = 'policy Schema 校验失败: ' + schemaErrs.slice(0, 5).join('; ')
      _cfgError = msg
      if (_cfg) return { cfg: _cfg, error: msg, fresh: false, stale: true }
      return { cfg: Object.assign({}, DEFAULT_CFG), error: msg, fresh: false, broken: true }
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
  // C13-01：失败时**不得**把内存里的旧 _scope 当当前授权返回。
  // 旧实现在 catch 里 `return { scope: _scope, ... }`，于是 evaluate 的 `if (!scope)`
  // 看到非 null 就跳过了整个拒绝分支 —— 删掉 scope.json 后授权仍然生效。
  // 现在：失败一律返回 scope: null；旧值只放 previous 供诊断，不参与判定。
  try {
    const raw = fs.readFileSync(scopePath(), 'utf8')
    const h = crypto.createHash('sha256').update(raw).digest('hex')
    if (h === _scopeHash && _scope) return { scope: _scope, error: null }
    let parsed
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      const prev = _scope
      _scopeError = 'scope JSON 解析失败: ' + String(e && e.message)
      _scope = null
      _scopeHash = null
      return { scope: null, previous: prev, error: _scopeError, broken: true, state: 'INVALID_SCOPE' }
    }
    _scope = parsed
    _scopeHash = h
    _scopeError = null
    return { scope: _scope, error: null }
  } catch (e) {
    const prev = _scope
    _scopeError = 'scope 读取失败: ' + String(e && e.message)
    _scope = null
    _scopeHash = null
    return { scope: null, previous: prev, error: _scopeError, missing: true, state: 'MISSING_SCOPE' }
  }
}

// ── agent 身份映射（P1-04：TTL + 清理）──────────────────────────────
const PRESET_BY_SESSION = new Map()   // sessionId -> { presetId, at }
// pre-execute 返回 ask 时把参数摘要存这里，供 approval/request 用 callId 关联
// （ApprovalRequest 里没有 arguments，拿不到参数哈希）
const PENDING_APPROVAL = new Map()   // callId -> { approvalId, argsHash, target, presetId, at, used }
// G-08：已批准的 callId -> approvalId。PENDING_APPROVAL 在配对完就删了，
// 但 tools/result 还需要知道"这次执行对应哪条审批"，所以单独留一份。
const APPROVED_CALLS = new Map()   // C13-07：加 TTL 与容量上限，否则批量子任务会把它撑大
const APPROVED_TTL_MS = 10 * 60 * 1000
const APPROVED_MAX = 5000

function pruneApproved(now) {
  const t = now || Date.now()
  for (const [k, v] of APPROVED_CALLS) {
    if (!v || (t - (v.at || 0)) > APPROVED_TTL_MS) APPROVED_CALLS.delete(k)
  }
  while (APPROVED_CALLS.size > APPROVED_MAX) {
    const first = APPROVED_CALLS.keys().next()
    if (first.done) break
    APPROVED_CALLS.delete(first.value)
  }
}
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

// G-09：严格校验。非法 IP / 非法掩码 / 越界分段一律返回 false（绝不当成授权命中）。
function parseIPv4Strict(s) {
  if (typeof s !== "string") return null
  const parts = s.split(".")
  if (parts.length !== 4) return null
  let v = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n < 0 || n > 255) return null
    v = (v * 256) + n
  }
  return v >>> 0
}

function ipInCidr(ip, cidr) {
  if (typeof cidr !== "string" || !cidr) return false
  const ipv = parseIPv4Strict(ip)
  if (ipv === null) return false
  if (!cidr.includes("/")) {
    const single = parseIPv4Strict(cidr)
    return single !== null && single === ipv
  }
  const parts = cidr.split("/")
  if (parts.length !== 2) return false
  const bitsRaw = parts[1]
  if (!/^\d{1,2}$/.test(bitsRaw)) return false
  const bits = Number(bitsRaw)
  if (bits < 0 || bits > 32) return false
  const basev = parseIPv4Strict(parts[0])
  if (basev === null) return false
  const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0)
  return ((ipv & mask) >>> 0) === ((basev & mask) >>> 0)
}

/** 授权是否在有效期内（P0-03 问题 H：expires 必须真正参与判断） */
// G-04：时间字段严格校验。解析失败不当作"没有限制"，一律拒绝。
function parseAuthTime(v, field) {
  if (v === undefined || v === null || v === "") return { ok: false, why: field + " 缺失或为空" }
  if (typeof v !== "string") return { ok: false, why: field + " 不是字符串" }
  const t = Date.parse(v)
  if (isNaN(t)) return { ok: false, why: field + " 无法解析为时间: " + JSON.stringify(v) }
  return { ok: true, t }
}

function authActive(sc, now = Date.now()) {
  const a = sc && sc.authorization
  if (!a) return { ok: true }   // 未配置 authorization 段 = 不做时效约束（兼容旧 scope）
  if (a.status !== undefined && String(a.status).toLowerCase() !== "active") {
    return { ok: false, why: "authorization.status=" + a.status }
  }
  let startT = null
  let endT = null
  if (a.startsAt !== undefined) {
    const r = parseAuthTime(a.startsAt, "startsAt")
    if (!r.ok) return { ok: false, why: "授权时间非法：" + r.why }
    startT = r.t
  }
  if (a.expiresAt !== undefined) {
    const r = parseAuthTime(a.expiresAt, "expiresAt")
    if (!r.ok) return { ok: false, why: "授权时间非法：" + r.why }
    endT = r.t
  }
  if (startT !== null && endT !== null && startT > endT) {
    return { ok: false, why: "authorization.startsAt 晚于 expiresAt" }
  }
  if (startT !== null && now < startT) return { ok: false, why: "授权尚未生效（startsAt=" + a.startsAt + "）" }
  if (endT !== null && now > endT) return { ok: false, why: "授权已过期（expiresAt=" + a.expiresAt + "）" }
  return { ok: true }
}

/** 单条 target 是否仍在有效期（兼容旧的 targets.<名字>.expires） */
function targetExpired(t, now = Date.now()) {
  if (!t || !t.expires) return false
  const raw = String(t.expires)
  const text = /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw + "T23:59:59" : raw
  const e = Date.parse(text)
  // G-04：解析不出来不能当作"未过期"——按失效处理（fail-closed）
  if (isNaN(e)) return true
  return now > e
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
  // C13-12：域名规则支持 exact / wildcard / subdomain；字符串写法等价于旧行为(subdomain)
  const domainRules = targetDomains.map(parseDomainRule)
  const serviceRules = (sc.serviceAllowlist || sc.excludeDomains || []).map(parseDomainRule)

  const bad = []
  for (const d of domains) {
    const dn = normDomain(d)
    if (domainMatchesAny(dn, domainRules)) continue
    if (domainMatchesAny(dn, serviceRules)) continue   // 辅助服务：允许访问，不等于授权测试
    if (allowUnlisted) continue
    bad.push({ kind: 'domain', value: d })
  }
  // G-09：ips 与 cidrs 合并判断。
  // 旧实现把 targets.ips 当"精确字符串"比、targets.cidrs 才做 CIDR，
  // 于是 ips 里写 203.0.113.0/24 永远匹配不到，而 999.1.1.1 因为字符串相等被当成合法授权。
  const ipRules = targetIps.concat(targetCidrs).filter((x) => typeof x === 'string' && x)
  const ipHit = (ip) => {
    const target = parseIPv4Strict(ip)
    if (target === null) return false               // 非法 IP 永不命中
    return ipRules.some((rule) => {
      if (rule.includes('/')) return ipInCidr(ip, rule)
      const single = parseIPv4Strict(rule)
      return single !== null && single === target    // 单 IP 也必须合法
    })
  }
  for (const ip of ips) {
    if (allowLocal && LOCAL_V4_RE.test(ip)) continue
    if (ipHit(ip)) continue
    if (allowUnlisted) continue
    bad.push({ kind: 'ip', value: ip })
  }
  // C13-13：IPv6 支持 CIDR（旧实现只做字符串精确比较）
  const v6Rules = []
  if (Array.isArray(sc.targets && sc.targets.ipv6)) v6Rules.push(...sc.targets.ipv6)
  for (const t of Object.values((sc.targets || {}))) {
    if (t && typeof t === 'object' && !targetExpired(t, now) && Array.isArray(t.ipv6)) v6Rules.push(...t.ipv6)
  }
  for (const ip of v6) {
    if (allowLocal && LOCAL_V6_RE.test(ip)) continue
    if (ipv6Hit(ip, v6Rules)) continue
    if (allowUnlisted) continue
    bad.push({ kind: 'ipv6', value: ip })
  }
  return { bad, unverifiable: false }
}

// ── C13-12：域名匹配模式 ────────────────────────────────────────────
// 旧实现 `d === x || d.endsWith('.' + x)` 只有一种语义：配 example.com 就自动
// 覆盖所有子域。审计要求把三种语义显式分开。
// 向后兼容：字符串写法仍按 subdomain 处理（等于旧行为），要严格就写成对象。
//   "a.com"                                  -> subdomain（兼容旧配置）
//   {name:"a.com", match:"exact"}            -> 只匹配 a.com
//   {name:"*.a.com", match:"wildcard"}       -> 匹配 x.a.com，不匹配 a.com 本身
//   {name:"a.com", match:"subdomain"}        -> a.com 及其所有子域
function normDomain(d) {
  let x = String(d || '').trim().toLowerCase().replace(/\.$/, '')
  // C13-11：IDNA 规范化（中文域名等）
  try {
    if (x && !/^[a-z0-9.*_-]+$/.test(x)) {
      const u = new URL('http://' + x + '/')
      x = u.hostname.toLowerCase().replace(/\.$/, '')
    }
  } catch (e) { /* 保持原样 */ }
  return x
}

function parseDomainRule(entry) {
  if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
    return { name: normDomain(entry.name), match: String(entry.match || 'subdomain').toLowerCase() }
  }
  return { name: normDomain(entry), match: 'subdomain' }
}

function domainRuleMatches(dn, rule, allowApexForWildcard) {
  const { name, match } = rule
  if (!name) return false
  if (match === 'exact') return dn === name
  if (match === 'wildcard') {
    const pattern = name.startsWith('*.') ? name.slice(2) : name
    if (dn === pattern) return allowApexForWildcard === true
    return dn.endsWith('.' + pattern)
  }
  // subdomain（默认，兼容旧行为）
  return dn === name || dn.endsWith('.' + name)
}

function domainMatchesAny(dn, rules, allowApexForWildcard) {
  for (const r of rules) if (domainRuleMatches(dn, r, allowApexForWildcard)) return r
  return null
}

// ── C13-13：IPv6 CIDR ───────────────────────────────────────────────
function ipv6ToBigInt(ip) {
  try {
    return require('node:net').isIPv6(ip) ? _v6ToBig(ip) : null
  } catch (e) { return null }
}

function _v6ToBig(ip) {
  let s = String(ip).trim()
  // IPv4-mapped: ::ffff:<IP>
  const m = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s)
  if (m) {
    const v4 = parseIPv4Strict(m[2])
    if (v4 === null) return null
    s = m[1] + ((v4 >>> 16) & 0xffff).toString(16) + ':' + (v4 & 0xffff).toString(16)
  }
  // 展开 ::
  const parts = s.split('::')
  if (parts.length > 2) return null
  const head = parts[0] ? parts[0].split(':').filter(Boolean) : []
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : []
  const fill = 8 - head.length - tail.length
  if (fill < 0) return null
  const groups = parts.length === 2 ? head.concat(Array(fill).fill('0'), tail) : head
  if (groups.length !== 8) return null
  let v = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
    v = (v << 16n) | BigInt(parseInt(g, 16))
  }
  return v
}

function ipv6InCidr(ip, cidr) {
  if (typeof cidr !== 'string' || !cidr.includes('/')) return false
  const [base, bitsRaw] = cidr.split('/')
  if (!/^\d{1,3}$/.test(bitsRaw)) return false
  const bits = Number(bitsRaw)
  if (bits < 0 || bits > 128) return false
  const ipv = _v6ToBig(ip)
  const basev = _v6ToBig(base)
  if (ipv === null || basev === null) return false
  const shift = BigInt(128 - bits)
  return (ipv >> shift) === (basev >> shift)
}

function ipv6Hit(ip, rules) {
  for (const r of rules) {
    if (typeof r !== 'string' || !r) continue
    if (r.includes('/')) { if (ipv6InCidr(ip, r)) return r }
    else {
      const a = _v6ToBig(ip); const b = _v6ToBig(r)
      if (a !== null && b !== null && a === b) return r
    }
  }
  return null
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

// G-10：serviceAllowlist 只代表"允许访问"，不代表"允许对它做攻击操作"。
// 用一个粗粒度的操作分类来区分：对辅助服务只允许只读类工具。
const READONLY_TOOL_RE = /^(web_fetch|web_search|read|read_image|glob|grep|skill|get_goal|list_agents|browser_read|browser_find|browser_view)$/

function toolClass(tool) {
  if (READONLY_TOOL_RE.test(tool)) return "read"
  if (/^redteam_/.test(tool)) return "attack"
  return "other"
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
  // G-02：先算出"是不是受保护工具 / 是不是 enforce"，身份未知时据此决定
  const presetId = presetOfAgent(ctx, exec)
  const enforcingEarly = String(cfg.mode || '').toLowerCase() === 'enforce'
  const protectedEarly = isProtected(tool, cfg)
  // C13-02：身份要求**不能**依赖 agents 是否为空。
  // 旧实现整段包在 `if (cfg.agents && Object.keys(cfg.agents).length)` 里，
  // 于是 `agents: {}` 就把 G-02 的身份拒绝逻辑一起绕过去了。
  const agentsHasRules = !!(cfg.agents && Object.keys(cfg.agents).length)
  const matchedKey = agentsHasRules
    ? Object.keys(cfg.agents).find((k) => presetMatchesKey(presetId, k))
    : null

  if (protectedEarly && enforcingEarly) {
    if (!presetId) {
      // 身份拿不到 -> 拒绝受保护工具（与 agents 是否为空无关）
      return {
        rule: 'agentUnknown',
        reason: `无法确认调用者角色（presetId=null），拒绝受保护工具 ${tool}`,
      }
    }
    if (!matchedKey && cfg.requireAgentIdentity === true) {
      return {
        rule: 'agentNoRule',
        reason: `角色 ${presetId} 没有匹配的权限规则，按 requireAgentIdentity 拒绝 ${tool}`,
      }
    }
  } else if (!presetId && cfg.requireAgentIdentity === true) {
    return { rule: 'agentUnknown', reason: `无法确认调用者角色（presetId=null），按策略拒绝 ${tool}` }
  }

  if (matchedKey) {
    const rule = cfg.agents[matchedKey] || {}
    const deny = Array.isArray(rule.deny) ? rule.deny : []
    const allow = Array.isArray(rule.allow) ? rule.allow : null
    if (allow) {
      if (!allow.includes(tool)) {
        return { rule: 'agentAllowlist', matched: matchedKey, reason: rule.reason || `角色 ${matchedKey} 未显式授权 ${tool}` }
      }
    } else if (deny.includes(tool)) {
      return { rule: 'agentDeny', matched: matchedKey, reason: rule.reason || `角色 ${matchedKey} 不允许调用 ${tool}` }
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

  // ⑤ 授权范围（P0-03；G-01：scope 不可用时受保护工具必须拒绝）
  const scopeInfo = loadScope()
  const scope = scopeInfo.scope
  const enforcingNow = String(cfg.mode || '').toLowerCase() === 'enforce'
  const protectedNow = isProtected(tool, cfg)

  if (!scope) {
    // v2.1.2 G-01 修复：旧实现在 scope 为 null 时直接 `if (scope)` 跳过，等于「授权文件没了就不用校验」。
    // 现在：受保护工具 + enforce 一律拒绝；其余情况放行但标记（reason 由调用方写审计）。
    if (protectedNow && enforcingNow) {
      return {
        rule: 'scopeUnavailable',
        reason: '授权范围文件不可用（' + (scopeInfo.error || '缺失') + '），拒绝受保护工具 ' + tool,
      }
    }
    return null
  }

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
    // G-10：参数里只命中 serviceAllowlist（不是授权目标）时，不允许用攻击类工具。
    // "允许访问 GitHub"不等于"允许对 GitHub 做漏洞测试"。
    try {
      const tg = extractTargets(args)
      const svc = (scope.serviceAllowlist || scope.excludeDomains || []).map((x) => String(x).toLowerCase())
      const tgtAll = []
      const t2 = scope.targets || {}
      if (Array.isArray(t2.domains)) tgtAll.push(...t2.domains)
      for (const x of Object.values(t2)) {
        if (x && typeof x === 'object') for (const d of (x.domains || [])) tgtAll.push(d)
      }
      const normT = tgtAll.map((x) => String(x).toLowerCase())
      const onlyService = [...tg.domains].length > 0
        && [...tg.domains].every((d) => svc.some((x) => d === x || d.endsWith('.' + x)))
        && ![...tg.domains].some((d) => normT.some((x) => d === x || d.endsWith('.' + x)))
      if (onlyService && toolClass(tool) === 'attack') {
        return {
          rule: 'serviceNoAttack',
          matched: [...tg.domains][0],
          reason: `目标只在辅助服务白名单里（${[...tg.domains][0]}），不构成对它做攻击操作的授权`,
        }
      }
    } catch (e) { /* ignore */ }
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

// C13-05：统一"最终会怎样"的判定，横幅/审计/pre-execute 都复用它。
// 旧实现横幅只看 mode、pre-execute 只看 enabled，于是 enabled=false + mode=enforce
// 会显示 "Blocking: YES" 而实际全部放行。
function effectiveMode(cfg, state) {
  if (!cfg || cfg.enabled === false) return "DISABLED"
  if (state === STATE.BLOCKED) return "BLOCKED"
  const m = String(cfg.mode || "").toLowerCase()
  if (m === "enforce") return state === STATE.DEGRADED ? "DEGRADED" : "ENFORCE"
  return "OBSERVE"
}

function willBlock(cfg, state) {
  const m = effectiveMode(cfg, state)
  return m === "ENFORCE" || m === "BLOCKED"
}


function isProtected(tool, cfg) {
  const extra = Array.isArray(cfg && cfg.protectedTools) ? cfg.protectedTools : []
  return DEFAULT_PROTECTED.includes(tool) || extra.includes(tool) || /^redteam_/.test(tool)
}

// ── C13-25：能力边界（必须说清，避免被误当成网络访问控制）───────────────
// 本插件工作在 tools/pre-execute，只能看到**工具参数**，据此做调用前决策
// （身份 / 工具权限 / Scope / 审批 / 参数校验）。
//
// 它**不能**保证工具实际连到的目标与参数声明一致 —— 以下都发生在插件可见范围之外：
//   · DNS 解析后的 IP、CNAME 链
//   · HTTP 重定向
//   · 代理出口
//   · 工具内部二次请求
//   · shell 命令里调用的其它程序
//
// 真正的网络强制需要另一层（受控代理 / 防火墙 / 目标 IP 校验 / 重定向校验）。
// runs/tools/net_observe.py 是**观测**，不是控制，不能拿它当访问限制。
// 要闭合这一层：在 Kali 上做出口白名单（iptables/nftables）或用受控代理做透明转发。

// ── 插件主体 ────────────────────────────────────────────────────────
// C13-15：幂等保护。同一个 ctx 重复 apply 会注册两套 pre-execute / approval / result
// 监听器 —— 每次工具调用检查两遍、审计写两条、session 映射更新两次。
// 用 WeakSet 记已注册的 ctx；不同 ctx（测试场景）仍然允许。
const _appliedCtxs = new WeakSet()
let _applyCount = 0

function apply(ctx, config) {
  // 说明：曾尝试读 apply 的第二个参数（Cordis 传 runtime.callback(ctx, config)），
  // 本地用 apply(ctx, {workspace}) 能读到，但在真实 DSH 进程里始终拿不到，
  // 且写入诊断的两条路径（process.cwd() / os.tmpdir()）都无输出、stderr 也不可见。
  // 结论：本插件不依赖 config，日志固定写在 WS（defaultWs() 解析结果）。
  // 要改 WS 请用环境变量 GUARDRAIL_WS 或 DSH_WORKSPACE。
  try {
    if (ctx && typeof ctx === 'object' && _appliedCtxs.has(ctx)) {
      process.stderr.write('[guardrail] WARN 同一个 ctx 重复 apply 被忽略（监听器已注册，不会再挂第二套）' + String.fromCharCode(10))
      return
    }
    if (ctx && typeof ctx === 'object') _appliedCtxs.add(ctx)
  } catch (e) { /* ignore */ }
  _applyCount += 1
  if (_applyCount > 1) {
    process.stderr.write('[guardrail] NOTE 这是本进程第 ' + _applyCount + ' 次 apply（不同 ctx，正常）' + String.fromCharCode(10))
  }
  // Cordis 的插件签名是 apply(ctx, config)：配置走**第二个参数**，不是 ctx.config。
  // 2026-11-19 实测：只写 apply(ctx) 时 config.workspace 永远读不到，
  // 插件 fallback 到 process.cwd()（= profile 目录），审计日志写错地方。
  try {
    // Cordis 源码（lib/index.js:365）：runtime.callback(this.ctx, config)
    // 所以 config 是第二参数；再兜 ctx.fiber.config（fiber 上保留的 rawConfig）。
    const cands = [config, ctx && ctx.fiber && ctx.fiber.config, ctx && ctx.config]
    for (const c of cands) {
      if (c && typeof c === 'object' && typeof c.workspace === 'string' && c.workspace) {
        WS = c.workspace
        break
      }
    }
  } catch (e) { /* ignore */ }
  if (!WS) WS = defaultWs()

  const cfgInfo0 = loadCfg()
  const scopeInfo0 = loadScope()
  const st0 = computeState(cfgInfo0, scopeInfo0)
  const cfg0 = cfgInfo0.cfg
  const stForBanner = computeState(cfgInfo0, scopeInfo0).state
  const effMode = effectiveMode(cfg0, stForBanner)
  const observing = !willBlock(cfg0, stForBanner)

  // P0-02：启动时必须明确「是否真的会拦」，不允许让人误以为已生效
  try {
    const bar = '='.repeat(64)
    const lines = [
      '',
      bar,
      ' Tool Guardrail Status',
      bar,
      ' Plugin Loaded  : YES  (v2.1.2, pid ' + PID + ', profile ' + PROFILE + ')',
      ' Policy Loaded  : ' + (cfgInfo0.broken ? 'BROKEN' : 'YES') + '  (' + policyPath() + ')',
      ' Scope Loaded   : ' + (scopeInfo0.missing ? 'MISSING' : scopeInfo0.broken ? 'BROKEN' : 'YES'),
      ' Agent Mapping  : ' + (PRESET_BY_SESSION.size ? 'READY' : 'WAITING (agent/created 后建立)'),
      ' Security State : ' + st0.state + (st0.reasons.length ? '  ← ' + st0.reasons.join('; ') : ''),
      ' Current Mode   : ' + effMode + (effMode === 'DISABLED' ? '  ← enabled=false，护栏整体关闭' : ''),
      ' Blocking       : ' + (observing ? 'NO' : 'YES'),
      ' Budget         : 仅记录（state.py 的 budget 字段），本插件**不做**预算拦截',
      ' --- 预检 ---',
      ...preflight().checks.map((c) => ' ' + (c[2] ? '[OK] ' : '[!!] ') + c[0] + ' = ' + c[1]),
      observing
        ? ' WARNING: 违规工具调用【不会】被拦截，只记录。要真正拦截请把 mode 改成 enforce。'
        : ' Blocking is ENABLED.',
      bar,
      '',
    ]
    process.stderr.write(lines.join('\n') + '\n')
  } catch (e) { /* 状态打印失败不影响主流程 */ }

  enqueue(cfg0.probeLog, {
    t: Date.now(), tag: 'plugin-loaded', version: '2.1.2',
    profile: PROFILE, pid: PID, workspace: wsLabel(WS),
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

        pruneApproved()
        noteSnapshot(cfg)
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

        // G-19：审计不可用时，受保护工具在 enforce 下必须拒绝（不能"干了但没记"）
        if ((AUDIT_BROKEN || AUDIT_OVERFLOW) && protectedTool && enforcing) {
          const why = AUDIT_BROKEN ? '审计日志写入持续失败' : '安全审计队列溢出'
          try {
            enqueue(cfg.auditLog, {
              t: Date.now(), tool, phase: 'pre-execute', decision: 'deny',
              rule: 'auditUnavailable', reason: why, presetId,
            })
          } catch (e) { /* ignore */ }
          return { kind: 'deny',
            reason: '[guardrail] ' + why + '，拒绝受保护工具 ' + tool + '（不能执行但无法留痕）',
            info: { name: 'GuardrailAuditUnavailable', code: 'GUARDRAIL_AUDIT_UNAVAILABLE' } }
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
            snapshotId: currentSnapshot().id,
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
                // C13-06 特别说明：DSH 的 ApprovalRequest 不携带 arguments，
                // 所以审批回调**无法**再校验一次参数摘要。这里明确记录绑定等级，
                // 不伪装成"审批时做了二次参数校验"。
                argumentBinding: 'PRE_EXECUTE_ONLY',
                approvalId: id,
                callId: exec.callId,
                agentId: exec.agent && exec.agent.id ? String(exec.agent.id) : null,
                presetId,
                toolName: tool,
                argsHash: argsHash(exec.arguments),
                target: [...tg.domains].slice(0, 3).join(',') || [...tg.ips].slice(0, 3).join(',') || null,
                at: Date.now(),
                used: false,
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
      // G-07：approvalId 必须与 pre-execute 阶段生成的那个是同一个。
      // 旧实现在这里又生成一个新 ID，导致同一次审批在审计里出现两个不同 ID。
      const pending = callId ? PENDING_APPROVAL.get(callId) : undefined
      const approvalId = (pending && pending.approvalId)
        || ('APR-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6))
      const cfg = loadCfg().cfg

      // G-03：只靠 callId 关联不够。逐项校验身份/工具/参数/时效/一次性。
      const APPROVAL_TTL_MS = 5 * 60 * 1000
      let mismatch = null
      // G-03 要求 6：一次性消费。若该工具本来要求审批，却没有对应的待审批记录
      // （已被消费 / 伪造 / 从未发起），不能当作"没约束"放行。
      const needPending = Array.isArray(cfg.approval && cfg.approval.tools) && cfg.approval.tools.includes(tool)
      if (needPending && !pending) {
        mismatch = '没有对应的待审批记录（已消费、伪造或未发起）'
      }
      if (pending) {
        if (pending.used) mismatch = '该审批已被使用过（一次性）'
        else if (pending.toolName && pending.toolName !== tool) mismatch = '工具名不一致: ' + pending.toolName + ' vs ' + tool
        else if (pending.agentId && !agentId) mismatch = '审批请求缺少 Agent 身份（pending 有记录，请求侧为空，无法验证）'
        else if (pending.agentId && agentId && pending.agentId !== String(agentId)) mismatch = 'Agent 身份不一致'
        else if (Date.now() - pending.at > APPROVAL_TTL_MS) mismatch = '审批请求已超时（>5min）'
        if (pending) pending.used = true
      }

      enqueue(cfg.auditLog, {
        t: Date.now(), phase: 'approval', decision: 'pending',
        approvalId, tool, callId, agentId: agentId ? String(agentId).slice(0, 40) : null,
        presetId: lookupPreset(agentId) || (pending && pending.presetId) || null,
        argsHash: pending ? pending.argsHash : null,
        ...hashMeta(),
        argumentBinding: pending ? (pending.argumentBinding || 'PRE_EXECUTE_ONLY') : null,
        target: pending ? pending.target : null,
        reason: req && req.reason || null,
        requestedAt: new Date().toISOString(),
      })

      let outcome = 'unavailable'
      let err = null
      try {
        if (mismatch) {
          // G-03：上下文不一致 → 不交给 UI，直接按未通过处理（fail-closed）
          err = 'approval context mismatch: ' + mismatch
          outcome = 'unavailable'
        } else {
          outcome = await next()          // 交给下游（DSH 的审批 UI）
        }
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
        ...hashMeta(),
        // C13-06：明确标注参数绑定等级。DSH 的 ApprovalRequest 不带 arguments，
        // 所以审批回调只能保证"pre-execute 阶段算过一次摘要"，不能宣称做了二次校验。
        argumentBinding: pending ? (pending.argumentBinding || 'PRE_EXECUTE_ONLY') : null,
        target: pending ? pending.target : null,
        // G-08：审批通过只能证明"用户允许执行"，**不能**证明工具真的执行成功。
        // 真实执行结果由 tools/result 另行记录（按 callId 关联），这里只标记"已批准待执行"。
        approved: outcome === 'allowed-once',
        executionPending: outcome === 'allowed-once',
        executionOutcome: null,
        decidedAt: new Date().toISOString(),
        error: err,
        mismatch: mismatch || undefined,
      })
      // 一次性：配对完就清 PENDING；但把 approvalId 留给 tools/result 关联执行结果
      if (callId) {
        if (outcome === 'allowed-once' && approvalId) {
          APPROVED_CALLS.set(callId, { approvalId, at: Date.now() })
          pruneApproved()
        }
        PENDING_APPROVAL.delete(callId)
      }
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
        const lifecycle = judgeExecution(result)
        const isErr = lifecycle === 'execution_failed' || lifecycle === 'execution_cancelled' || lifecycle === 'execution_timeout'
        // G-08：把「执行结果」与「审批批准」分开记。
        // 审批通过只证明"用户允许执行"，执行成功与否要由这里判定。
        enqueue(cfg.auditLog, {
          t: Date.now(), tool: exec && exec.name, callId: exec && exec.callId,
          isError: isErr, phase: 'result',
          lifecycle,
        })
        // 若这个 callId 走过审批，补一条带结果的关联记录（审计只追加，不改旧记录）
        if (exec && exec.callId && APPROVED_CALLS.has(exec.callId)) {
          const apRec = APPROVED_CALLS.get(exec.callId)
          const apId = apRec && apRec.approvalId
          APPROVED_CALLS.delete(exec.callId)     // 执行结果只记一次
          enqueue(cfg.auditLog, {
            t: Date.now(), phase: 'execution', callId: exec.callId,
            tool: exec.name, approvalId: apId,
            lifecycle,
            isError: isErr,
          })
        }
      } catch (e) { /* ignore */ }
    })
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-registered' })
  } catch (e) {
    enqueue(cfg0.probeLog, { t: Date.now(), tag: 'result-hook-failed', error: String(e && e.message) })
  }
}

export { name, inject, apply, evaluate, loadCfg, loadScope, outOfScope, redactValue, presetMatchesKey, flush as flushLogs, authActive, targetExpired, ipInCidr, extractTargets, parseIPv4Strict, setWorkspace, effectiveMode, willBlock, pruneApproved, judgeExecution, safeLogPath, wsLabel, hashMeta, canonicalize, parseDomainRule, domainRuleMatches, ipv6InCidr, normDomain }
