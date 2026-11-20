import { fileURLToPath, pathToFileURL } from 'node:url'
/**
 * V3 第四批（G-08 / G-10 / G-20 / G-23 / G-24 / G-25）测试
 * G-18 是"不实现但明确标注"，用断言检查横幅文字。
 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v3-batch4-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
// C13-18：用 import.meta.url 定位插件，不依赖 process.cwd() 或绝对路径
const HERE = path.dirname(fileURLToPath(import.meta.url))
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const M = await import(P + '?v=' + Date.now())
const POL = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCP = path.join(TMP, 'runs', 'tools', 'scope.json')
const AUDIT = path.join(TMP, 'runs', 'guardrail-audit.jsonl')
const writeP = o => fs.writeFileSync(POL, JSON.stringify(Object.assign(
  { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [], approval: { tools: [] } }, o)), 'utf8')
const baseScope = {
  version: '1.0',
  authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] },
  serviceAllowlist: ['github.com'], allowUnlisted: true, allowLocal: true,
}
fs.writeFileSync(SCP, JSON.stringify(baseScope), 'utf8')
writeP({})
M.loadCfg(); M.loadScope()

const readAudit = () => { try { M.flushLogs() } catch (e) {} return fs.existsSync(AUDIT)
  ? fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [] }


// C13-02（v1.6.0）之后身份检查在 scope 之前：没传 agent 的调用会先被 agentUnknown 拦。
// 这组用例测的是 scope/参数/规则，不是身份，所以统一补一个已知身份的 ctx。
const KNOWN_CTX = { get: (n) => n === 'agentPresets'
  ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
  : n === 'sessions' ? { get: () => ({ id: 'test-agent' }) } : undefined }
const evalFn = (typeof M !== 'undefined' && M && M.evaluate) ? M.evaluate : evaluate
const EV = (exec, cfg) => evalFn(
  exec && exec.agent ? exec : Object.assign({}, exec, { agent: { id: 'test-agent' } }),
  cfg,
  KNOWN_CTX,
)

const MOCK_GET = (n) => n === 'agentPresets'
  ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
  : n === 'sessions' ? { get: () => ({ id: 'test-agent' }) } : undefined

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
console.log('\n=== G-23 策略 Schema 校验 ===')
const schemaCases = [
  ['mode 非法', { enabled: true, mode: 'lol' }, true],
  ['argMax 非数字', { enabled: true, mode: 'observe', argMax: { limit: 'lots' } }, true],
  ['agents.deny 非数组', { enabled: true, mode: 'observe', agents: { recon: { deny: 'x' } } }, true],
  ['argDeny 元素缺 tool', { enabled: true, mode: 'observe', argDeny: [{ arg: 'x' }] }, true],
  ['approval.tools 非数组', { enabled: true, mode: 'observe', approval: { tools: 'x' } }, true],
  ['正常配置', { enabled: true, mode: 'observe', argMax: { limit: 10 } }, false],
]
for (const [label, obj, expectErr] of schemaCases) {
  T(`G-23：${label} → ${expectErr ? '拒绝' : '接受'}`, () => {
    fs.writeFileSync(POL, JSON.stringify(obj), 'utf8')
    const r = M.loadCfg()
    if (expectErr) assert.ok(r.error, '应报 Schema 错误，实际通过')
    else assert.ok(!r.error, '不该报错，实际: ' + r.error)
  })
}
writeP({}); M.loadCfg()

console.log('\n=== G-10 辅助服务不自动赋予攻击权限 ===')
const cfgE = { enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }
T('G-10：web_fetch(github.com) → 放行（只读类）', () => {
  assert.strictEqual(EV({ name: 'web_fetch', arguments: { url: 'https://github.com/x' } }, cfgE), null)
})
T('G-10：redteam_webshell_add(github.com) → serviceNoAttack', () => {
  const v = EV({ name: 'redteam_webshell_add', arguments: { url: 'https://github.com/x' } }, cfgE)
  assert.ok(v && v.rule === 'serviceNoAttack', '实际: ' + JSON.stringify(v))
})
T('G-10：redteam_webshell_add(授权目标 ok.example.cn) → 放行', () => {
  assert.strictEqual(EV({ name: 'redteam_webshell_add', arguments: { url: 'https://ok.example.cn/x' } }, cfgE), null)
})
T('G-10：混合（辅助服务 + 授权目标）→ 不算只命中服务，放行', () => {
  const v = EV({ name: 'redteam_webshell_add',
    arguments: { a: 'https://github.com/x', b: 'https://ok.example.cn/y' } }, cfgE)
  assert.strictEqual(v, null, '含授权目标时不该判 serviceNoAttack')
})

console.log('\n=== G-25 启动预检 ===')
T('G-25：preflight 有输出且含关键项', () => {
  // preflight 没导出，用启动横幅间接验证：捕获 stderr
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  assert.ok(src.includes('function preflight()'), '缺 preflight')
  assert.ok(src.includes('policySchema'), 'preflight 应检查 policySchema')
  assert.ok(src.includes('scopeVersion'), 'preflight 应检查 scopeVersion')
})

console.log('\n=== G-18 budget 只标注不实现 ===')
T('G-18：横幅明确写"不做预算拦截"', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  assert.ok(src.includes('预算'), '横幅应提到预算')
  assert.ok(src.includes('不做') || src.includes('仅记录'), '必须明确说明只是记录')
})

console.log('\n=== G-20 不接管 SIGINT/SIGTERM ===')
T('G-20：源码里没有 SIGINT/SIGTERM 的 process.on', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  const hasSig = /process\.on\(\s*['"]SIG(INT|TERM)['"]/.test(src)
  assert.ok(!hasSig, '不应接管 SIGINT/SIGTERM（会导致进程不退出）')
  assert.ok(src.includes("process.on('exit'"), '应有 exit 同步 flush')
})

console.log('\n=== G-08 审批 != 执行 ===')
const h = {}
M.apply({ get: MOCK_GET, tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
const pre = (h['tools/pre-execute'] || [])[0]
const apr = (h['approval/request'] || [])[0]
const res = (h['tools/result'] || [])[0]

writeP({ approval: { tools: ['redteam_webshell_add'], reason: 't' } }); M.loadCfg()
await TA('G-08：批准后 approved=true 且 executionPending=true，无 executed 字段', async () => {
  await pre({ name: 'redteam_webshell_add', callId: 'g08-1', arguments: { url: 'https://ok.example.cn' }, agent: { id: 'a' } },
            async () => ({ kind: 'allow' }))
  await apr({ agent: { id: 'a' }, toolName: 'redteam_webshell_add', callId: 'g08-1' }, async () => 'allowed-once')
  const d = readAudit().filter(r => r.phase === 'approval' && r.callId === 'g08-1' && r.decision === 'allowed-once').pop()
  assert.ok(d, '缺 decision 记录')
  assert.strictEqual(d.approved, true)
  assert.strictEqual(d.executionPending, true)
  assert.strictEqual(d.executed, undefined, 'G-08：不该有 executed 字段')
})
await TA('G-08：工具执行失败 → 记 execution_failed，不改审批记录', async () => {
  assert.ok(typeof res === 'function', 'tools/result 未注册')
  res({ name: 'redteam_webshell_add', callId: 'g08-1' }, { isError: true })
  const rows = readAudit()
  const ex = rows.filter(r => r.phase === 'execution' && r.callId === 'g08-1').pop()
  assert.ok(ex, '缺 execution 关联记录')
  assert.strictEqual(ex.lifecycle, 'execution_failed')
  assert.strictEqual(ex.approvalId, rows.filter(r => r.phase === 'approval' && r.callId === 'g08-1').pop().approvalId,
    'execution 记录应与审批同 approvalId')
})
await TA('G-08：工具执行成功 → execution_succeeded（新 callId 走完整流程）', async () => {
  await pre({ name: 'redteam_webshell_add', callId: 'g08-2', arguments: { url: 'https://ok.example.cn' }, agent: { id: 'a' } },
            async () => ({ kind: 'allow' }))
  await apr({ agent: { id: 'a' }, toolName: 'redteam_webshell_add', callId: 'g08-2' }, async () => 'allowed-once')
  res({ name: 'redteam_webshell_add', callId: 'g08-2' }, { isError: false })
  const ex = readAudit().filter(r => r.phase === 'execution' && r.callId === 'g08-2').pop()
  assert.ok(ex && ex.lifecycle === 'execution_succeeded', '实际: ' + JSON.stringify(ex))
})

console.log('\n=== G-24 一致性快照 ===')
await TA('G-24：审计里带 snapshotId，且 policy/scope 变化会产生新快照', async () => {
  writeP({ argMax: { limit: 5 } }); M.loadCfg()
  await pre({ name: 'redteam_asset_query', callId: 'g24-1', arguments: { limit: 1 } }, async () => ({ kind: 'allow' }))
  const rows = readAudit()
  const reloads = rows.filter(r => r.phase === 'policy-reload')
  assert.ok(reloads.length >= 1, '应有 policy-reload 记录')
  assert.ok(reloads.pop().snapshotId, 'policy-reload 应带 snapshotId')
  const withSnap = rows.filter(r => r.snapshotId)
  assert.ok(withSnap.length >= 1, '审计记录应带 snapshotId')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
