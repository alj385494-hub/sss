import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v3p0-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
const P = 'file:///' + path.join(process.cwd(), 'runs/plugins/dsh-tool-guardrail/lib/index.js').split(path.sep).join('/')
const M = await import(P + '?v=' + Date.now())
const POLICY = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCOPE = path.join(TMP, 'runs', 'tools', 'scope.json')
const writePolicy = o => fs.writeFileSync(POLICY, JSON.stringify(Object.assign(
  { enabled: true, mode: 'enforce', agents: {}, toolDeny: {}, argMax: {}, argDeny: [] }, o)), 'utf8')
const baseScope = { authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] }, allowUnlisted: false, allowLocal: true }
fs.writeFileSync(SCOPE, JSON.stringify(baseScope), 'utf8')
M.loadScope(); M.loadCfg()

let pass = 0, fail = 0
const T = (l, f) => { try { f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }

// ── G-02 ──
writePolicy({ agents: { recon: { allow: ['redteam_asset_query'] } } })
M.loadCfg()
T('G-02：身份未知 + 受保护工具(redteam_score_hit) + enforce → agentUnknown', () => {
  const v = M.evaluate({ name: 'redteam_score_hit', arguments: {}, agent: { id: 'nobody' } },
                        { enabled: true, mode: 'enforce', agents: { recon: { allow: [] } } }, { get: () => undefined })
  assert.ok(v, '应拒绝，实际放行'); assert.strictEqual(v.rule, 'agentUnknown')
})
T('G-02：身份未知 + 普通工具(bash) → 放行（不误伤）', () => {
  const v = M.evaluate({ name: 'bash', arguments: {}, agent: { id: 'nobody' } },
                        { enabled: true, mode: 'enforce', agents: { recon: { allow: [] } } }, { get: () => undefined })
  assert.strictEqual(v, null)
})
T('G-02：身份未知 + observe → 放行（observe 不拦）', () => {
  const v = M.evaluate({ name: 'redteam_score_hit', arguments: {}, agent: { id: 'nobody' } },
                        { enabled: true, mode: 'observe', agents: { recon: { allow: [] } } }, { get: () => undefined })
  assert.strictEqual(v, null)
})

// ── G-04 边界 ──
const evalWithAuth = (auth) => {
  fs.writeFileSync(SCOPE, JSON.stringify(Object.assign({}, baseScope, { authorization: auth })), 'utf8')
  M.loadScope()
  return M.evaluate({ name: 'redteam_webshell_add', arguments: { url: 'https://ok.example.cn' } },
                    { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }, undefined)
}
T('G-04：expiresAt=null → 拒绝', () => { const v = evalWithAuth({ status: 'active', expiresAt: null }); assert.ok(v && v.rule === 'scopeExpired', JSON.stringify(v)) })
T('G-04：expiresAt=乱码 → 拒绝', () => { const v = evalWithAuth({ status: 'active', expiresAt: '20-13-99' }); assert.ok(v && v.rule === 'scopeExpired') })
T('G-04：已过期(2020) → 拒绝', () => { const v = evalWithAuth({ status: 'active', expiresAt: '2020-01-01T00:00:00Z' }); assert.ok(v && v.rule === 'scopeExpired') })
T('G-04：未来时间 → 放行', () => { const v = evalWithAuth({ status: 'active', expiresAt: '2030-01-01T00:00:00Z' }); assert.strictEqual(v, null) })
T('G-04：status=revoked → 拒绝', () => { const v = evalWithAuth({ status: 'revoked', expiresAt: '2030-01-01T00:00:00Z' }); assert.ok(v && v.rule === 'scopeExpired') })

// ── G-03 审批上下文 ──
// 注意：G-04 最后一个用例把 scope 改成了 status=revoked，这里必须重置，
// 否则 evaluate 会提前命中 scopeExpired，走不到审批分支（测试 setup 缺陷，不是代码问题）
fs.writeFileSync(SCOPE, JSON.stringify(baseScope), 'utf8')
M.loadScope()
writePolicy({ approval: { tools: ['redteam_webshell_add'], reason: 'test' } })
M.loadCfg()
const h = {}
M.apply({ tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
const pre = (h['tools/pre-execute'] || [])[0]
const apr = (h['approval/request'] || [])[0]

await (async () => {
  // 正常流程
  await pre({ name: 'redteam_webshell_add', callId: 'ok1', arguments: { url: 'https://ok.example.cn' }, agent: { id: 'a1' } }, async () => ({ kind: 'allow' }))
  const r1 = await apr({ agent: { id: 'a1' }, toolName: 'redteam_webshell_add', callId: 'ok1' }, async () => 'allowed-once')
  T('G-03：上下文一致 → 透传 allowed-once', () => assert.strictEqual(r1, 'allowed-once'))

  // 工具名不一致
  await pre({ name: 'redteam_webshell_add', callId: 'bad1', arguments: {}, agent: { id: 'a1' } }, async () => ({ kind: 'allow' }))
  let nextCalled = false
  const r2 = await apr({ agent: { id: 'a1' }, toolName: 'redteam_credential_add', callId: 'bad1' }, async () => { nextCalled = true; return 'allowed-once' })
  T('G-03：工具名不一致 → 不交给 UI，按 unavailable', () => {
    assert.strictEqual(r2, 'unavailable'); assert.strictEqual(nextCalled, false, '不该调用下游')
  })

  // Agent 不一致
  await pre({ name: 'redteam_webshell_add', callId: 'bad2', arguments: {}, agent: { id: 'a1' } }, async () => ({ kind: 'allow' }))
  const r3 = await apr({ agent: { id: 'a2' }, toolName: 'redteam_webshell_add', callId: 'bad2' }, async () => 'allowed-once')
  T('G-03：Agent 不一致 → unavailable', () => assert.strictEqual(r3, 'unavailable'))

  // 一次性
  const r4 = await apr({ agent: { id: 'a1' }, toolName: 'redteam_webshell_add', callId: 'ok1' }, async () => 'allowed-once')
  T('G-03：重复使用同一审批 → unavailable', () => assert.strictEqual(r4, 'unavailable'))

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
  process.exit(fail === 0 ? 0 : 1)
})()
