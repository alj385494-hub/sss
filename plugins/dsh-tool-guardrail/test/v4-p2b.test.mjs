/** V4 P2-b（C13-21 / C13-22 / C13-23）测试 */
import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const TMP = path.join(os.tmpdir(), 'dsh-guardrail-p2b-' + process.pid)
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
const M = await import(pathToFileURL(path.resolve(HERE, '../lib/index.js')).href + '?v=' + Date.now())
const POL = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCP = path.join(TMP, 'runs', 'tools', 'scope.json')
const AUD = path.join(TMP, 'runs', 'guardrail-audit.jsonl')

fs.writeFileSync(SCP, JSON.stringify({
  version: '1.0', authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] }, serviceAllowlist: [], allowUnlisted: true,
}), 'utf8')

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
// 深链构造器
const deep = (leaf, n) => { let o = leaf; for (let i = 0; i < n; i++) o = { a: o }; return o }

console.log('\n=== C13-21 规范化不静默压缩 ===')
T('C13-21：深度 10 的两种不同叶子 → 规范化结果不同（旧实现深度>8 会撞成 "[deep]"）', () => {
  const a = M.canonicalize(deep('X', 10))
  const b = M.canonicalize(deep('Y', 10))
  assert.ok(a && b, '不该是 null')
  assert.notStrictEqual(a, b, '两个不同的深层参数得到了相同规范化结果')
})
T('C13-21：超出最大深度 → 返回 null（判不可验证），不压缩成占位符', () => {
  assert.strictEqual(M.canonicalize(deep('X', 70)), null)
})
T('C13-21：数组里的超深元素也让整体判 null', () => {
  const v = { list: [deep('X', 70)] }
  assert.strictEqual(M.canonicalize(v), null)
})
T('C13-21：hashMeta 带算法与规范化版本', () => {
  const h = M.hashMeta()
  assert.strictEqual(h.hashAlgorithm, 'sha256')
  assert.strictEqual(typeof h.canonicalizationVersion, 'number')
  assert.ok(h.canonicalizationVersion >= 1)
})
T('C13-21：key 顺序不影响结果（规范化仍在）', () => {
  assert.strictEqual(M.canonicalize({ a: 1, b: 2 }), M.canonicalize({ b: 2, a: 1 }))
})

console.log('\n=== C13-22 Policy Schema 加强 ===')
const schemaCases = [
  // 未知字段的处置改了：只警告不拒绝（加新字段就整份策略失效的代价太大），所以这里期望 false
  ['未知字段（aproval 拼错）→ 只警告不拒绝', { enabled: true, mode: 'observe', aproval: {} }, false],
  ['approval.tools 元素非字符串', { enabled: true, mode: 'observe', approval: { tools: [123] } }, true],
  ['approval.reason 过长', { enabled: true, mode: 'observe', approval: { reason: 'x'.repeat(300) } }, true],
  ['protectedTools 元素非字符串', { enabled: true, mode: 'observe', protectedTools: [null] }, true],
  ['argDeny 元素 tool 过长', { enabled: true, mode: 'observe', argDeny: [{ tool: 'x'.repeat(300), arg: 'a' }] }, true],
  ['toolDeny 值过长', { enabled: true, mode: 'observe', toolDeny: { t: 'y'.repeat(300) } }, true],
  ['argMax 负数', { enabled: true, mode: 'observe', argMax: { limit: -1 } }, true],
  ['argMax 天文数字', { enabled: true, mode: 'observe', argMax: { limit: 1e12 } }, true],
  ['正常配置', { enabled: true, mode: 'observe', policyVersion: '1.0' }, false],
]
for (const [label, obj, shouldErr] of schemaCases) {
  T(`C13-22：${label} → ${shouldErr ? '拒绝' : '接受'}`, () => {
    fs.writeFileSync(POL, JSON.stringify(obj), 'utf8')
    const r = M.loadCfg()
    if (shouldErr) assert.ok(r.error, '应报 Schema 错误，实际通过')
    else assert.ok(!r.error, '不该报错，实际: ' + r.error)
  })
}

console.log('\n=== C13-23 快照带 Schema 版本 ===')
fs.writeFileSync(POL, JSON.stringify({
  enabled: true, mode: 'observe', policyVersion: '1.2', agents: {}, argMax: {}, argDeny: [],
}), 'utf8')
M.loadCfg(); M.loadScope()
const h = {}
M.apply({ get: (n) => n === 'agentPresets' ? { presetForSession: () => 'p', composedPreset: () => 'p' }
  : n === 'sessions' ? { get: () => ({ id: 's' }) } : undefined,
  tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
const pre = (h['tools/pre-execute'] || [])[0]

await TA('C13-23：policy-reload 记录同时带 policy 与 scope 的 schema 版本', async () => {
  await pre({ name: 'bash', arguments: {}, callId: 'c1' }, async () => ({ kind: 'allow' }))
  try { M.flushLogs() } catch (e) {}
  const rows = fs.existsSync(AUD) ? fs.readFileSync(AUD, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : []
  const rl = rows.filter((r) => r.phase === 'policy-reload').pop()
  assert.ok(rl, '缺 policy-reload 记录，现有 phase: ' + [...new Set(rows.map((r) => r.phase))].join(','))
  assert.strictEqual(rl.policySchemaVersion, '1.2', 'policySchemaVersion: ' + rl.policySchemaVersion)
  assert.strictEqual(rl.scopeSchemaVersion, '1.0', 'scopeSchemaVersion: ' + rl.scopeSchemaVersion)
  assert.ok(rl.snapshotId, '缺 snapshotId')
})

await TA('C13-23：policy 版本变了 → snapshotId 变、并记新版本', async () => {
  const before = fs.readFileSync(AUD, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
    .filter((r) => r.phase === 'policy-reload').pop().snapshotId
  fs.writeFileSync(POL, JSON.stringify({
    enabled: true, mode: 'observe', policyVersion: '1.3', agents: {}, argMax: {}, argDeny: [],
  }), 'utf8')
  M.loadCfg()
  await pre({ name: 'bash', arguments: {}, callId: 'c2' }, async () => ({ kind: 'allow' }))
  try { M.flushLogs() } catch (e) {}
  const rows = fs.readFileSync(AUD, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
  const rl = rows.filter((r) => r.phase === 'policy-reload').pop()
  assert.notStrictEqual(rl.snapshotId, before, '内容变了 snapshotId 应变化')
  assert.strictEqual(rl.policySchemaVersion, '1.3')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
