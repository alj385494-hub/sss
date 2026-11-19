/**
 * P1-02 审批闭环测试 —— 对应第二轮审计"Agency 审批系统"的 12 条要求。
 *
 * 关键事实（从 DSH 源码确认，不是猜的）：
 *   · `approval/request` 是 waterfall：`(req, next) => Promise<ApprovalOutcome>`
 *   · ApprovalRequest 只有 `{agent, toolName, callId, reason, displayReason, signal}` —— **没有 arguments**
 *   · ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'
 *   · `allowed-once` 是 DSH 自己的语义：审批只生效一次 → 天然满足"审批不能重复使用"
 *
 * 所以我做的是：**观测 + 关联 + 落审计**，不改变 DSH 的审批语义。
 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

const TMP = path.join(process.cwd(), 'runs', 'tmp', 'guardrail-approval-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
for (const f of ['guardrail-policy.json', 'scope.json']) {
  const src = path.join(process.cwd(), 'runs', 'tools', f)
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(TMP, 'runs', 'tools', f))
}
process.env.GUARDRAIL_WS = TMP

const P = 'file:///' + path.join(process.cwd(), 'runs/plugins/dsh-tool-guardrail/lib/index.js').replace(/\\/g, '/')
const { apply, flushLogs } = await import(P + '?v=' + Date.now())

const AUDIT = path.join(TMP, 'runs', 'guardrail-audit.jsonl')
const readAudit = () => { try { flushLogs() } catch (e) {}
  return fs.existsSync(AUDIT)
  ? fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
  : []
}

// 让插件切一致模式
const POLICY = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
fs.writeFileSync(POLICY, JSON.stringify({
  enabled: true, mode: 'enforce', policyVersion: '1.1',
  agents: {}, toolDeny: {}, argMax: {}, argDeny: [],
  approval: { tools: ['redteam_webshell_add'], reason: '测试：需人工确认' },
}, null, 2), 'utf8')

let pass = 0, fail = 0
const TA = async (label, fn) => {
  try { await fn(); console.log('  ✅', label); pass++ }
  catch (e) { console.log('  ❌', label, '→', e.message); fail++ }
}

function newPlugin() {
  const g = [], h = {}
  apply({ tools: { guard: (f) => g.push(f) }, on: (e, f) => { (h[e] ||= []).push(f) } })
  return h
}

console.log('\n=== P1-02 审批闭环 ===')

const h = newPlugin()

await TA('approval/request 钩子已注册', () => {
  assert.ok((h['approval/request'] || []).length >= 1, '未注册')
})

await TA('allowed-once：记录 pending + 最终 decision，approved 后才 executed=true', async () => {
  const pre = h['tools/pre-execute'][0]
  const apr = h['approval/request'][0]
  const before = readAudit().length

  // 1) pre-execute 返回 ask，并把参数摘要存进 PENDING_APPROVAL
  const gate = await pre(
    { name: 'redteam_webshell_add', callId: 'call-A1', arguments: { url: 'https://a.example.cn/x', password: 'p@ss' } },
    async () => ({ kind: 'allow' }),
  )
  assert.strictEqual(gate.kind, 'ask', '应返回 ask，实际 ' + JSON.stringify(gate))
  assert.ok(String(gate.reason).includes('需人工确认'))

  // 2) DSH 发起审批，下游用户点同意
  const outcome = await apr(
    { agent: { id: 'sess-1' }, toolName: 'redteam_webshell_add', callId: 'call-A1', reason: '需人工确认' },
    async () => 'allowed-once',
  )
  assert.strictEqual(outcome, 'allowed-once', '必须原样透传下游结果')

  const rows = readAudit().slice(before).filter((r) => r.phase === 'approval')
  const pending = rows.find((r) => r.decision === 'pending')
  const decided = rows.find((r) => r.decision === 'allowed-once')
  assert.ok(pending, '缺 pending 记录')
  assert.ok(decided, '缺 decision 记录')
  assert.strictEqual(pending.approvalId, decided.approvalId, 'pending 与 decision 的 approvalId 必须一致')
  assert.ok(pending.argsHash && pending.argsHash.startsWith('sha256:'), '缺参数哈希')
  assert.strictEqual(decided.approved, true, 'allowed-once 应标 approved=true')
  assert.strictEqual(decided.executionPending, true, '批准后应是「待执行」，而不是「已执行」')
  assert.strictEqual(decided.executed, undefined, 'G-08：不应再有 executed 字段（审批通过不等于执行成功）')
  assert.ok(!JSON.stringify(rows).includes('p@ss'), '参数明文泄露进审计！')
})

await TA('rejected：executed=false', async () => {
  const pre = h['tools/pre-execute'][0]
  const apr = h['approval/request'][0]
  await pre({ name: 'redteam_webshell_add', callId: 'call-A2', arguments: { url: 'https://b.example.cn' } },
    async () => ({ kind: 'allow' }))
  await apr({ agent: { id: 'sess-1' }, toolName: 'redteam_webshell_add', callId: 'call-A2' },
    async () => 'rejected')
  const d = readAudit().filter((r) => r.phase === 'approval' && r.decision === 'rejected').pop()
  assert.ok(d, '缺 rejected 记录')
  assert.strictEqual(d.approved, false, '被拒绝不该标 approved')
})

await TA('cancelled：也算未执行', async () => {
  const apr = h['approval/request'][0]
  await apr({ agent: { id: 'sess-1' }, toolName: 'x', callId: 'call-A3' }, async () => 'cancelled')
  const d = readAudit().filter((r) => r.phase === 'approval' && r.decision === 'cancelled').pop()
  assert.ok(d)
  assert.strictEqual(d.approved, false)
})

await TA('审批链抛异常 → 按 unavailable 落库（fail-closed，不静默）', async () => {
  const apr = h['approval/request'][0]
  const outcome = await apr({ agent: { id: 'sess-1' }, toolName: 'y', callId: 'call-A4' },
    async () => { throw new Error('answerer boom') })
  assert.strictEqual(outcome, 'unavailable', '异常应归一为 unavailable')
  const d = readAudit().filter((r) => r.phase === 'approval' && r.callId === 'call-A4').pop()
  assert.ok(d && d.error, '应记录错误')
})

await TA('approvalId 唯一（不同审批不撞号）', async () => {
  const apr = h['approval/request'][0]
  const ids = []
  for (let i = 0; i < 5; i++) {
    await apr({ agent: { id: 's' }, toolName: 'z', callId: 'uniq-' + i }, async () => 'rejected')
  }
  for (const r of readAudit().filter((x) => x.phase === 'approval' && x.decision === 'rejected')) ids.push(r.approvalId)
  assert.strictEqual(new Set(ids).size, ids.length, 'approvalId 有重复: ' + ids.join(','))
})

await TA('参数变化 → argsHash 变化（要求重新审批的基础）', async () => {
  const pre = h['tools/pre-execute'][0]
  const apr = h['approval/request'][0]
  const hashes = []
  for (const [i, url] of ['https://c1.example.cn', 'https://c2.example.cn'].entries()) {
    const cid = 'hash-' + i
    await pre({ name: 'redteam_webshell_add', callId: cid, arguments: { url } }, async () => ({ kind: 'allow' }))
    await apr({ agent: { id: 's' }, toolName: 'redteam_webshell_add', callId: cid }, async () => 'allowed-once')
    const d = readAudit().filter((r) => r.phase === 'approval' && r.callId === cid && r.decision === 'allowed-once').pop()
    hashes.push(d && d.argsHash)
  }
  assert.ok(hashes[0] && hashes[1], '两次都要有 argsHash')
  assert.notStrictEqual(hashes[0], hashes[1], '不同参数应产生不同哈希')
})

await TA('target 被记录（审计要求 5：审批绑定最终目标）', async () => {
  const d = readAudit().filter((r) => r.phase === 'approval' && r.callId === 'call-A1').pop()
  assert.ok(d && d.target, '缺 target')
  assert.ok(String(d.target).includes('a.example.cn'), 'target 不对: ' + d.target)
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
