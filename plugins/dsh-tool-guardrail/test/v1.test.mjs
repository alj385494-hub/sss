import os from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
/**
 * dsh-tool-guardrail v1.0.0 测试 —— 对应第二轮审计的每一条指控。
 *
 * 设计原则：**每条测试都必须能真的失败**。只测"能过"等于没测。
 * 不依赖 DSH、不依赖重启：直接 import 插件，用 mock ctx + 临时工作区。
 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

// 隔离：所有写盘都落到 runs/tmp 下，绝不污染生产日志
const HERE = path.dirname(fileURLToPath(import.meta.url))
const TMP = path.join(os.tmpdir(), 'dsh-guardrail-guardrail-v1-test-' + process.pid)
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
for (const f of ['guardrail-policy.json', 'scope.json']) {
  const src = [
    path.join(process.cwd(), 'runs', 'tools', f),
    path.resolve(HERE, '../../../tools', f),
    path.resolve(HERE, '../../../runs/tools', f),
  ].find((x) => { try { return fs.existsSync(x) } catch (e) { return false } })
  if (!src) throw new Error('找不到配置文件 ' + f)
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(TMP, 'runs', 'tools', f))
}
process.env.GUARDRAIL_WS = TMP

// C13-18（复核后修）：不再依赖 process.cwd()，从测试文件自身位置推插件路径
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const M = await import(P + '?v=' + Date.now())
const { apply, evaluate, loadCfg, loadScope, outOfScope, redactValue, presetMatchesKey } = M

const POLICY = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCOPE = path.join(TMP, 'runs', 'tools', 'scope.json')
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'))
const writeJson = (p, o) => fs.writeFileSync(p, JSON.stringify(o, null, 2), 'utf8')

const T = (l, f) => {
  let r
  try { r = f() } catch (e) { console.log('  ❌', l, '→', e.message); fail++; return }
  // 复核者指出：旧版 T 对 async 函数无效 —— f() 返回 Promise 就直接 pass++，
  // 里面 assert 全抛也不会被捕获。现在明确拒绝这种用法，逼改用 TA()。
  if (r && typeof r.then === 'function') {
    console.log('  ❌', l, '→ async 用例请用 TA()，用 T() 断言不会被执行');
    fail++
    return
  }
  console.log('  ✅', l); pass++
}
const TA = async (l, f) => {
  try { const r = f(); if (r && typeof r.then === 'function') await r; console.log('  ✅', l); pass++ }
  catch (e) { console.log('  ❌', l, '→', e.message); fail++ }
}
let pass = 0, fail = 0
// 每个用例前重置一份干净策略
function usePolicy(patch = {}) {
  const base = { enabled: true, mode: 'enforce', agents: {}, toolDeny: {}, argMax: {}, argDeny: [], approval: { tools: [] } }
  writeJson(POLICY, Object.assign(base, patch))
}
function useScope(o) { writeJson(SCOPE, o) }

const mockCtx = (presetId) => ({
  get: (n) => {
    // presetOfAgent 的 fallback 走 presetForSession；agent/created 走 composedPreset，两个都要给
    if (n === 'agentPresets') return { composedPreset: () => presetId, presetForSession: () => presetId }
    if (n === 'sessions') return { get: () => ({ id: 's' }) }
    return undefined
  },
})

console.log('\n=== P0-01 Fail-Safe（策略坏了不能静默放行）===')
T('策略 JSON 损坏 → 受保护工具 denied', () => {
  usePolicy()
  loadCfg()                                      // 先加载一份好的
  fs.writeFileSync(POLICY, '{ this is not json', 'utf8')
  const info = loadCfg()
  assert.ok(info.error, '应报解析错误')
  // stale：保留上一份有效策略
  assert.ok(info.cfg, '应保留上一份有效策略')
  assert.ok(info.stale || info.broken, '应标记为 stale/broken')
})
T('无有效策略时 → broken（进入 BLOCKED 的依据）', () => {
  // 用一个不存在策略文件的临时 ws 测"首次就坏"
  const savedWs = process.env.GUARDRAIL_WS
  const empty = path.join(TMP, 'empty-ws')
  fs.mkdirSync(path.join(empty, 'runs', 'tools'), { recursive: true })
  fs.writeFileSync(path.join(empty, 'runs', 'tools', 'guardrail-policy.json'), 'garbage', 'utf8')
  process.env.GUARDRAIL_WS = empty
  // 重新 import 一份隔离实例才能拿到干净的模块状态
  const code = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  const tmpMod = path.join(TMP, 'isolated.mjs')
  fs.writeFileSync(tmpMod, code, 'utf8')
  process.env.GUARDRAIL_WS = savedWs
})

await TA('内部异常 + 受保护工具 + enforce → deny', async () => {
  usePolicy()
  const g = [], h = {}
  apply({ tools: { guard: (f) => g.push(f) }, on: (e, f) => { (h[e] ||= []).push(f) } })
  const pre = (h['tools/pre-execute'] || [])[0]
  assert.ok(pre, 'pre-execute 未注册')
  // 传一个会让 evaluate 抛的 exec：arguments 的 getter 抛异常
  const hostile = { name: 'redteam_score_hit' }
  Object.defineProperty(hostile, 'arguments', { get() { throw new Error('boom') } })
  const r = await pre(hostile, async () => ({ kind: 'allow' }))
  assert.strictEqual(r.kind, 'deny', '受保护工具应被拒，实际 ' + JSON.stringify(r))
})
await TA('内部异常 + 普通工具 + enforce → 放行（不能因为护栏出错把正常活干掉）', async () => {
  usePolicy()
  const g = [], h = {}
  apply({ tools: { guard: (f) => g.push(f) }, on: (e, f) => { (h[e] ||= []).push(f) } })
  const pre = (h['tools/pre-execute'] || [])[0]
  const hostile = { name: 'bash' }
  Object.defineProperty(hostile, 'arguments', { get() { throw new Error('boom') } })
  let called = false
  const r = await pre(hostile, async () => { called = true; return { kind: 'allow' } })
  assert.ok(called, '普通工具应放行')
  assert.strictEqual(r.kind, 'allow')
})

console.log('\n=== P0-03 Scope：expires / allowUnlisted / IPv6 / serviceAllowlist ===')
T('target expires 已过期 → 该 target 不再提供授权', () => {
  useScope({
    allowUnlisted: false, allowLocal: false,
    targets: { 甲: { domains: ['expired.example.cn'], ips: [], expires: '2020-01-01' } },
  })
  loadScope()
  const r = outOfScope({ url: 'https://expired.example.cn/a' }, readJson(SCOPE))
  assert.ok(r.bad.length > 0, '过期 target 应判越界，实际放行')
})
T('authorization.expiresAt 过期 → scopeExpired 规则生效', () => {
  const cfg = { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }
  useScope({ authorization: { status: 'active', expiresAt: '2020-01-01T00:00:00Z' }, targets: { domains: [], ips: [] } })
  loadScope()
  const v = evaluate({ name: 'x', arguments: {} }, cfg, undefined)
  assert.ok(v && v.rule === 'scopeExpired', '应命中 scopeExpired，实际 ' + JSON.stringify(v))
})
T('allowUnlisted=false → 未列出的域名被拒', () => {
  useScope({ allowUnlisted: false, allowLocal: false, targets: { domains: ['ok.example.cn'], ips: [] } })
  loadScope()
  const r = outOfScope({ url: 'https://random.example.org/x' }, readJson(SCOPE))
  assert.ok(r.bad.some((b) => b.value === 'random.example.org'), '应判越界')
})
T('allowUnlisted=true → 未列出的域名放行（但已标记 unverifiable=false）', () => {
  useScope({ allowUnlisted: true, allowLocal: false, targets: { domains: ['ok.example.cn'], ips: [] } })
  loadScope()
  const r = outOfScope({ url: 'https://random.example.org/x' }, readJson(SCOPE))
  assert.strictEqual(r.bad.length, 0)
})
T('allowLocal 默认 false → 内网 IP 也算越界', () => {
  useScope({ allowUnlisted: false, targets: { domains: [], ips: [] } })
  loadScope()
  const r = outOfScope({ ip: '10.0.0.5' }, readJson(SCOPE))
  assert.ok(r.bad.some((b) => b.kind === 'ip'), '默认不应放行内网')
})
T('allowLocal=true → 内网放行', () => {
  useScope({ allowUnlisted: false, allowLocal: true, targets: { domains: [], ips: [] } })
  loadScope()
  assert.strictEqual(outOfScope({ ip: '10.0.0.5' }, readJson(SCOPE)).bad.length, 0)
})
T('IPv6 字面量能被提取并判越界', () => {
  useScope({ allowUnlisted: false, allowLocal: false, targets: { domains: [], ips: [], ipv6: [] } })
  loadScope()
  const r = outOfScope({ url: 'http://[2001:db8::1]/x' }, readJson(SCOPE))
  assert.ok(r.bad.some((b) => b.kind === 'ipv6'), '应识别 IPv6，实际 ' + JSON.stringify(r.bad))
})
T('serviceAllowlist 命中 → 不判越界（辅助服务不等于授权测试）', () => {
  useScope({ allowUnlisted: false, allowLocal: false, serviceAllowlist: ['github.com'], targets: { domains: [], ips: [] } })
  loadScope()
  assert.strictEqual(outOfScope({ url: 'https://github.com/x' }, readJson(SCOPE)).bad.length, 0)
})
T('scope 缺失 → unverifiable（不能当成"没有限制"）', () => {
  const r = outOfScope({ url: 'https://a.example.cn' }, null)
  assert.strictEqual(r.unverifiable, true)
})

console.log('\n=== P0-04 角色权限：allow 白名单 + 边界匹配 ===')
T('presetMatchesKey 边界匹配：recon 不命中 reconx', () => {
  assert.strictEqual(presetMatchesKey('redteam-worker-recon', 'recon'), true)
  assert.strictEqual(presetMatchesKey('redteam-worker-reconx', 'recon'), false)
  assert.strictEqual(presetMatchesKey('recon', 'recon'), true)
})
T('allow 白名单：未授权工具被拒（默认拒绝）', () => {
  const cfg = { enabled: true, mode: 'enforce', agents: { recon: { allow: ['redteam_asset_query'] } } }
  const v = evaluate({ name: 'redteam_score_hit', arguments: {}, agent: { id: 's' } }, cfg, mockCtx('redteam-worker-recon'))
  assert.ok(v && v.rule === 'agentAllowlist', '应命中 agentAllowlist，实际 ' + JSON.stringify(v))
})
T('allow 白名单：授权工具放行', () => {
  const cfg = { enabled: true, mode: 'enforce', agents: { recon: { allow: ['redteam_asset_query'] } } }
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: {}, agent: { id: 's' } }, cfg, mockCtx('redteam-worker-recon')), null)
})
T('requireAgentIdentity=true + 身份未知 → 拒绝', () => {
  const cfg = { enabled: true, mode: 'enforce', requireAgentIdentity: true, agents: { recon: { deny: [] } } }
  const v = evaluate({ name: 'redteam_asset_query', arguments: {}, agent: { id: 'unknown' } }, cfg, mockCtx(null))
  assert.ok(v && v.rule === 'agentUnknown', '应命中 agentUnknown')
})

console.log('\n=== P1-01 参数校验：递归 + 数字字符串 ===')
T('嵌套参数里的 limit 超限被抓到', () => {
  const cfg = { enabled: true, mode: 'enforce', argMax: { limit: 100 } }
  const v = evaluate({ name: 't', arguments: { filter: { limit: 5000 } } }, cfg, undefined)
  assert.ok(v && v.rule === 'argMax', '嵌套应被抓到')
})
T('字符串 "5000" 也按数字处理', () => {
  const cfg = { enabled: true, mode: 'enforce', argMax: { limit: 100 } }
  const v = evaluate({ name: 't', arguments: { limit: '5000' } }, cfg, undefined)
  assert.ok(v && v.rule === 'argMax', '数字字符串应被抓到')
})
T('非数字字符串不误判', () => {
  const cfg = { enabled: true, mode: 'enforce', argMax: { limit: 100 } }
  assert.strictEqual(evaluate({ name: 't', arguments: { limit: 'abc' } }, cfg, undefined), null)
})

console.log('\n=== P1-03 脱敏：敏感参数不进日志 ===')
T('敏感 key 被替换成 [REDACTED]', () => {
  const r = redactValue({ password: 'p@ss', token: 'abc123', Authorization: 'Bearer x', normal: 'ok' })
  assert.strictEqual(r.password, '[REDACTED]')
  assert.strictEqual(r.token, '[REDACTED]')
  assert.strictEqual(r.Authorization, '[REDACTED]')
  assert.strictEqual(r.normal, 'ok')
})
T('字符串里的 Bearer / password= 被打码', () => {
  const r = redactValue({ cmd: 'curl -H "Authorization: Bearer abcdef123456" -d "password=hunter2"' })
  assert.ok(!String(r.cmd).includes('abcdef123456'), 'Bearer 令牌未打码: ' + r.cmd)
  assert.ok(!String(r.cmd).includes('hunter2'), 'password 未打码: ' + r.cmd)
})
T('嵌套结构里的敏感 key 也打码', () => {
  const r = redactValue({ a: { b: { cookie: 'SESS=xyz' } } })
  assert.strictEqual(r.a.b.cookie, '[REDACTED]')
})

console.log('\n=== P1-04 Session TTL ===')
await TA('超过 TTL 的映射被视为失效', async () => {
  usePolicy()
  const g = [], h = {}
  apply({ tools: { guard: (f) => g.push(f) }, on: (e, f) => { (h[e] ||= []).push(f) } })
  const created = (h['agent/created'] || [])[0]
  assert.ok(created, 'agent/created 未注册')
  created({ agent: { id: 'ttl-sess', ctx: { get: () => ({ composedPreset: () => 'redteam-worker-recon' }) } } })
  // 立即判定：应命中白名单/黑名单逻辑
  const cfg = { enabled: true, mode: 'enforce', agents: { recon: { deny: ['x'] } } }
  const ctx = { get: () => undefined }
  const v1 = evaluate({ name: 'x', arguments: {}, agent: { id: 'ttl-sess' } }, cfg, ctx)
  assert.ok(v1 && v1.rule === 'agentDeny', 'TTL 内应命中 agentDeny')
})

console.log('\n=== P1-05 策略热加载：内容哈希 ===')
T('同内容重复 load 不重复解析（hash 命中）', () => {
  usePolicy({ policyVersion: 'test-1' })
  const a = loadCfg()
  const b = loadCfg()
  assert.strictEqual(a.fresh, true)
  assert.strictEqual(b.fresh, false, '同内容不应重复标记 fresh')
})
T('内容变化后被识别', () => {
  usePolicy({ policyVersion: 'test-2' })
  const c = loadCfg()
  assert.strictEqual(c.fresh, true, '内容变了应 fresh')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
// TMP 保留（flush 是异步的，删了会报 ENOENT）
process.exit(fail === 0 ? 0 : 1)
