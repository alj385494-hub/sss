/**
 * judge_scope.mjs —— 目标授权的**唯一判定入口**（G-14）
 *
 * 为什么单独一个脚本：
 *   插件（JS，跑在 DSH 进程里）和 net_observe.py（Python，跑在命令行）各自实现一套判定，
 *   迟早会出现"同一个目标在主护栏判为授权内、在网络报告判为越界"。
 *   这里直接 import 插件的 outOfScope / authActive，Python 通过子进程调用它，
 *   保证两边用的是**同一份代码**。
 *
 * 用法：
 *   echo '{"workspace":"...","domains":["a.com"],"ips":["1.2.3.4"]}' | node judge_scope.mjs
 *
 * 输出（stdout，JSON）：
 *   {
 *     "ok": true,
 *     "authorization": {"ok": true, "why": null},
 *     "domains": {"a.com": "target"|"service"|"out"|"unknown"},
 *     "ips":     {"1.2.3.4": "target"|"local"|"out"|"unknown"},
 *     "reason": null
 *   }
 *   ok=false 表示判不出来（scope 缺失/损坏/授权失效），调用方**不能**当成"没有越界"。
 */
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'

function readStdin() {
  return new Promise((resolve) => {
    let buf = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (c) => { buf += c })
    process.stdin.on('end', () => resolve(buf))
    if (process.stdin.isTTY) resolve('{}')
  })
}

function fail(msg) {
  process.stdout.write(JSON.stringify({ ok: false, reason: msg, domains: {}, ips: {} }))
  process.exit(0)
}

const raw = (await readStdin()).trim() || '{}'
let req
try {
  req = JSON.parse(raw)
} catch (e) {
  fail('输入不是合法 JSON: ' + String(e && e.message))
}

// 定位插件：允许显式传入，否则按默认位置找
const PLUGIN = req.plugin
  || path.join(process.cwd(), 'runs', 'plugins', 'dsh-tool-guardrail', 'lib', 'index.js')

let M
try {
  M = await import('file:///' + PLUGIN.split(path.sep).join('/'))
} catch (e) {
  fail('加载插件失败: ' + String(e && e.message))
}

// MSYS/Git-Bash 风格的 /c/xxx 要转成 C:/xxx，Node 不认前者
function normPath(p) {
  if (!p || typeof p !== 'string') return p
  const m = /^\/([a-zA-Z])(\/.*)?$/.exec(p)
  if (m) return m[1].toUpperCase() + ':' + (m[2] || '/')
  return p
}

if (req.workspace && typeof M.setWorkspace === 'function') {
  M.setWorkspace(normPath(req.workspace))
}

const { scope } = M.loadScope()
if (!scope) {
  fail('授权范围文件不可用（缺失或解析失败）——不能据此得出"没有越界"的结论')
}

// 1) 授权本身是否有效（G-14：时间有效性必须复用主引擎的判断）
let auth
try {
  auth = M.authActive(scope)
} catch (e) {
  fail('授权有效性判定异常: ' + String(e && e.message))
}
if (!auth || auth.ok !== true) {
  process.stdout.write(JSON.stringify({
    ok: false,
    reason: '授权无效: ' + ((auth && auth.why) || '未知原因'),
    authorization: auth,
    domains: {}, ips: {},
  }))
  process.exit(0)
}

// 2) 逐类判定。
//    注意语义：这里回答的是「**是不是显式授权的目标**」，不是「护栏会不会拦」。
//    两者会不同：scope.allowUnlisted=true 时护栏不拦未列出目标，但它仍然不是授权目标。
//    报告要说清这一点，否则"没被拦"会被误读成"已授权"。
const domains = {}
const ips = {}

const tgt = scope.targets || {}
const now = Date.now()

// 收集显式授权域名（含旧结构，且排除已过期的 target）
const tgtDomains = []
const collectFrom = (obj) => {
  for (const t of Object.values(obj || {})) {
    if (!t || typeof t !== 'object') continue
    if (M.targetExpired(t, now)) continue          // 过期 target 不再提供授权
    for (const d of (t.domains || [])) tgtDomains.push(d)
  }
}
if (Array.isArray(tgt.domains)) tgtDomains.push(...tgt.domains)
collectFrom(tgt)
collectFrom(tgt.$legacy)

const normTargets = tgtDomains.map((x) => String(x).toLowerCase().replace(/\.$/, ''))
const service = (scope.serviceAllowlist || scope.excludeDomains || []).map((x) => String(x).toLowerCase())

for (const d of req.domains || []) {
  const dn = String(d).toLowerCase().replace(/\.$/, '')
  if (normTargets.some((x) => x && (dn === x || dn.endsWith('.' + x)))) domains[d] = 'target'
  else if (service.some((x) => x && (dn === x || dn.endsWith('.' + x)))) domains[d] = 'service'
  else domains[d] = 'out'
}

// 收集显式授权 IP / CIDR
const ipRules = []
if (Array.isArray(tgt.ips)) ipRules.push(...tgt.ips)
if (Array.isArray(tgt.cidrs)) ipRules.push(...tgt.cidrs)
for (const t of Object.values(tgt)) {
  if (t && typeof t === 'object' && !M.targetExpired(t, now)) {
    for (const i of (t.ips || [])) ipRules.push(i)
  }
}
for (const t of Object.values(tgt.$legacy || {})) {
  if (t && typeof t === 'object' && !M.targetExpired(t, now)) {
    for (const i of (t.ips || [])) ipRules.push(i)
  }
}

const ipHit = (clean) => {
  if (M.parseIPv4Strict(clean) === null) return false
  return ipRules.some((rule) => {
    if (typeof rule !== 'string' || !rule) return false
    if (rule.includes('/')) return M.ipInCidr(clean, rule)
    return M.parseIPv4Strict(rule) === M.parseIPv4Strict(clean)
  })
}

for (const ip of req.ips || []) {
  const clean = String(ip).split(':')[0]
  if (M.parseIPv4Strict(clean) === null) { ips[ip] = 'invalid'; continue }
  if (ipHit(clean)) { ips[ip] = 'target'; continue }
  const local = /^(127\.|10\.|192\.168\.|169\.254\.)/.test(clean)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(clean)
  ips[ip] = local ? 'local' : 'out'
}

process.stdout.write(JSON.stringify({
  ok: true,
  authorization: auth,
  domains,
  ips,
  schemaVersion: 1,
}))
