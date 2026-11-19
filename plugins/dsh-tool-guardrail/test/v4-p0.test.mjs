import { fileURLToPath, pathToFileURL } from 'node:url'
/** V4 P0（C13-01/02/03）测试 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v4-p0-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
// C13-18：用 import.meta.url 定位插件，不依赖 process.cwd() 或绝对路径
const HERE = path.dirname(fileURLToPath(import.meta.url))
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const M = await import(P + '?v=' + Date.now())
const POL = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCP = path.join(TMP, 'runs', 'tools', 'scope.json')
const writeP = o => fs.writeFileSync(POL, JSON.stringify(Object.assign(
  { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [], approval: { tools: [] } }, o)), 'utf8')
const goodScope = {
  version: '1.0',
  authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] },
  serviceAllowlist: [], allowUnlisted: false, allowLocal: true,
}
fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8')
writeP({}); M.loadCfg(); M.loadScope()

let pass = 0, fail = 0
const T = (l, f) => { try { f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }
const cfgE = () => ({ enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] })
// C13-02 之后身份检查在 scope 之前，所以测 scope 时必须给一个已知身份，
// 否则会先被 agentUnknown 拦下（那是正确行为，但不是本组用例要测的）
const knownCtx = { get: (n) => n === 'agentPresets'
  ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
  : n === 'sessions' ? { get: () => ({ id: 's' }) } : undefined }
const withAgent = (name, args) => ({ name, arguments: args || {}, agent: { id: 's' } })

console.log('\n=== C13-01：scope 文件失败后不得沿用旧授权 ===')
T('正常加载后，授权内目标放行', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()
  assert.strictEqual(M.evaluate(withAgent('redteam_webshell_add', { url: 'https://ok.example.cn' }), cfgE(), knownCtx), null)
})
T('删掉 scope.json → 受保护工具必须被拒（不能沿用内存旧授权）', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()   // 先加载一份
  fs.rmSync(SCP)
  const info = M.loadScope()
  assert.strictEqual(info.scope, null, '失败时必须返回 scope=null')
  assert.ok(info.missing, '应标 missing')
  const v = M.evaluate(withAgent('redteam_webshell_add', { url: 'https://ok.example.cn' }), cfgE(), knownCtx)
  assert.ok(v && v.rule === 'scopeUnavailable', '应拒绝，实际 ' + JSON.stringify(v))
})
T('scope 变成非法 JSON → 受保护工具必须被拒', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()
  fs.writeFileSync(SCP, '{ broken', 'utf8')
  const info = M.loadScope()
  assert.strictEqual(info.scope, null)
  assert.ok(info.broken)
  const v = M.evaluate(withAgent('redteam_score_hit'), cfgE(), knownCtx)
  assert.ok(v && v.rule === 'scopeUnavailable')
})
T('scope 截断内容 → 必须被拒', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()
  fs.writeFileSync(SCP, JSON.stringify(goodScope).slice(0, 20), 'utf8')
  const info = M.loadScope()
  assert.strictEqual(info.scope, null)
})
T('普通工具不受影响（不误伤）', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()
  fs.rmSync(SCP); M.loadScope()
  assert.strictEqual(M.evaluate({ name: 'bash', arguments: {} }, cfgE(), undefined), null)
})

console.log('\n=== C13-02：agents={} 不能绕过身份要求 ===')
T('agents={} + 身份未知 + 受保护工具 + enforce → 必须拒绝', () => {
  fs.writeFileSync(SCP, JSON.stringify(goodScope), 'utf8'); M.loadScope()
  const v = M.evaluate({ name: 'redteam_webshell_add', arguments: { url: 'https://ok.example.cn' } },
                       { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }, { get: () => undefined })
  assert.ok(v && v.rule === 'agentUnknown', '被绕过了！实际: ' + JSON.stringify(v))
})
T('agents 为空 + 身份未知 + 普通工具 → 放行（不误伤）', () => {
  const v = M.evaluate({ name: 'bash', arguments: {} },
                       { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }, { get: () => undefined })
  assert.strictEqual(v, null)
})
T('身份已识别但无规则 + requireAgentIdentity=true → agentNoRule', () => {
  const ctxMock = { get: (n) => n === 'agentPresets' ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
                                    : n === 'sessions' ? { get: () => ({ id: 's' }) } : undefined }
  const v = M.evaluate({ name: 'redteam_score_hit', arguments: {}, agent: { id: 's' } },
                       { enabled: true, mode: 'enforce', agents: { recon: { deny: [] } }, requireAgentIdentity: true,
                         argMax: {}, argDeny: [] }, ctxMock)
  assert.ok(v && v.rule === 'agentNoRule', '实际: ' + JSON.stringify(v))
})

console.log('\n=== C13-03：重试耗尽必须置 AUDIT_BROKEN ===')
T('审计写到不可写路径 → 重试耗尽后 AUDIT_BROKEN 生效，受保护工具被拒', async () => {
  const bad = Object.assign({}, goodScope)
  fs.writeFileSync(SCP, JSON.stringify(bad), 'utf8'); M.loadScope()
  writeP({ auditLog: 'runs/__nope__/deep/audit.jsonl', probeLog: 'runs/__nope__/probe.log' })
  M.loadCfg()
  const h = {}; M.apply({ tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
  const pre = (h['tools/pre-execute'] || [])[0]
  // 触发大量写失败
  for (let i = 0; i < 30; i++) {
    try { M.flushLogs() } catch (e) {}
    await pre({ name: 'bash', arguments: {}, callId: 'x' + i }, async () => ({ kind: 'allow' }))
    try { M.flushLogs() } catch (e) {}
  }
  const r = await pre({ name: 'redteam_score_hit', arguments: {}, callId: 'final' }, async () => ({ kind: 'allow' }))
  assert.ok(r && r.kind === 'deny', '审计不可用时受保护工具必须被拒，实际: ' + JSON.stringify(r))
  assert.ok(String(r.reason).includes('审计'), '理由应说明审计问题: ' + r.reason)
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
