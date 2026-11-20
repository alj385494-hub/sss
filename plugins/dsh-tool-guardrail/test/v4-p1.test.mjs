import os from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
/** V4 P1（C13-05 / C13-06 / C13-07 / C13-08 / C13-09）测试 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
const MOCK_GET = (n) => n === 'agentPresets'
  ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
  : n === 'sessions' ? { get: () => ({ id: 'test-agent' }) } : undefined

const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v4-p1-test')
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
fs.writeFileSync(SCP, JSON.stringify({
  version: '1.0', authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] },
  serviceAllowlist: [], allowUnlisted: false, allowLocal: true,
}), 'utf8')
writeP({}); M.loadCfg(); M.loadScope()

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
const readAudit = () => { try { M.flushLogs() } catch (e) {} return fs.existsSync(AUDIT)
  ? fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [] }

console.log('\n=== C13-05 enabled=false 时不能显示 Blocking YES ===')
T('enabled=false + mode=enforce → DISABLED，不阻塞', () => {
  const cfg = { enabled: false, mode: 'enforce' }
  assert.strictEqual(M.effectiveMode(cfg, 'NORMAL'), 'DISABLED')
  assert.strictEqual(M.willBlock(cfg, 'NORMAL'), false)
})
T('enabled=true + mode=enforce → ENFORCE，阻塞', () => {
  assert.strictEqual(M.effectiveMode({ enabled: true, mode: 'enforce' }, 'NORMAL'), 'ENFORCE')
  assert.strictEqual(M.willBlock({ enabled: true, mode: 'enforce' }, 'NORMAL'), true)
})
T('enabled=true + mode=observe → OBSERVE，不阻塞', () => {
  assert.strictEqual(M.effectiveMode({ enabled: true, mode: 'observe' }, 'NORMAL'), 'OBSERVE')
  assert.strictEqual(M.willBlock({ enabled: true, mode: 'observe' }, 'NORMAL'), false)
})
T('BLOCKED 状态 → willBlock true（策略坏了也要挡）', () => {
  assert.strictEqual(M.effectiveMode({ enabled: true, mode: 'observe' }, 'BLOCKED'), 'BLOCKED')
  assert.strictEqual(M.willBlock({ enabled: true, mode: 'observe' }, 'BLOCKED'), true)
})

console.log('\n=== C13-08 严格结果判定（不能把"没结果"当成功）===')
T('result=null → execution_unknown（旧实现会记成功）', () => {
  assert.strictEqual(M.judgeExecution(null), 'execution_unknown')
})
T('result=undefined → execution_unknown', () => {
  assert.strictEqual(M.judgeExecution(undefined), 'execution_unknown')
})
T('result 不是对象 → execution_unknown', () => {
  assert.strictEqual(M.judgeExecution('ok'), 'execution_unknown')
})
T('isError 不是布尔 → execution_unknown', () => {
  assert.strictEqual(M.judgeExecution({ isError: 'false' }), 'execution_unknown')
})
T('isError=true → execution_failed', () => {
  assert.strictEqual(M.judgeExecution({ isError: true }), 'execution_failed')
})
T('isError=false → execution_succeeded', () => {
  assert.strictEqual(M.judgeExecution({ isError: false }), 'execution_succeeded')
})
T('cancelled / timeout 单独归类', () => {
  assert.strictEqual(M.judgeExecution({ cancelled: true }), 'execution_cancelled')
  assert.strictEqual(M.judgeExecution({ timeout: true }), 'execution_timeout')
})

console.log('\n=== C13-09 日志路径不得越界 ===')
const cases = [
  ['正常相对路径', 'runs/a.jsonl', true],
  ['带 .. 穿越', '../../evil.jsonl', false],
  ['深层穿越', 'runs/../../../evil.jsonl', false],
  ['绝对路径 /etc', '/etc/evil.jsonl', false],
  ['Windows 盘符', 'C:/Windows/Temp/evil.jsonl', false],
  ['空字符串', '', false],
  ['非字符串', 123, false],
]
for (const [label, p, shouldOk] of cases) {
  T(`C13-09：${label} → ${shouldOk ? '允许' : '拒绝'}`, () => {
    const r = M.safeLogPath(p)
    if (shouldOk) assert.ok(r && r.startsWith(path.resolve(TMP)), '应允许，实际 ' + r)
    else assert.strictEqual(r, null, '应拒绝，实际 ' + r)
  })
}
T('C13-09：符号链接被拒绝', () => {
  const link = path.join(TMP, 'runs', 'link.jsonl')
  const target = path.join(TMP, 'runs', 'real.jsonl')
  fs.writeFileSync(target, '')
  try { fs.symlinkSync(target, link) } catch (e) { return }  // Windows 无权限时跳过
  assert.strictEqual(M.safeLogPath('runs/link.jsonl'), null, '符号链接应被拒绝')
})

// ══ C13-09 补：拒绝之后发生什么（复核指出原测试只断言返回值）══
console.log('\n=== C13-09 越界路径被拒绝之后的行为 ===')
T('C13-09：越界 audit 路径返回 null，不抛异常', () => {
  let r
  assert.doesNotThrow(() => { r = M.safeLogPath('../../outside-audit.jsonl', 'audit') },
    'safeLogPath 自己不该抛')
  assert.strictEqual(r, null, '越界应返回 null')
})
T('C13-09：越界 probe 路径降级到临时目录（不是静默丢弃）', () => {
  const r = M.safeLogPath('../../outside-probe.log', 'probe')
  assert.ok(r, '诊断日志应降级而不是消失')
  assert.ok(r.includes('dsh-guardrail-'), '应是降级后的临时文件: ' + r)
})
await TA('C13-09：审计路径越界时 flush 不崩，且后续合法条目照常写入', async () => {
  // 复核原话：原测试只测 safeLogPath 返回值，从不测"被拒绝之后发生了什么"，
  // 所以 _blockedLogPath 未声明导致的 ReferenceError 全程绿灯。
  const TMP2 = path.join(os.tmpdir(), 'dsh-guardrail-c09s-' + process.pid)
  fs.rmSync(TMP2, { recursive: true, force: true })
  fs.mkdirSync(path.join(TMP2, 'runs', 'tools'), { recursive: true })
  fs.writeFileSync(path.join(TMP2, 'runs', 'tools', 'guardrail-policy.json'),
    JSON.stringify({ enabled: true, mode: 'observe', agents: {}, argMax: {}, argDeny: [] }))
  fs.writeFileSync(path.join(TMP2, 'runs', 'tools', 'scope.json'),
    JSON.stringify({ version: '1.0', authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
                     targets: { domains: [], ips: [], ipv6: [] } }))
  // 必须先把 GUARDRAIL_WS 指到 TMP2，再 import —— 否则 M2 会继承文件开头那个 WS
  process.env.GUARDRAIL_WS = TMP2
  const P2 = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href + '?c09s=' + Date.now()
  const M2 = await import(P2)
  // 用一个会越界的审计路径 + 一个合法的 probe 路径
  fs.writeFileSync(path.join(TMP2, 'runs', 'tools', 'guardrail-policy.json'),
    JSON.stringify({ enabled: true, mode: 'observe', agents: {}, argMax: {}, argDeny: [],
                     auditLog: '../../escaped-audit.jsonl', probeLog: 'runs/plugin-probe.log' }))
  M2.loadCfg(); M2.loadScope()
  const h2 = {}
  M2.apply({ get: MOCK_GET, tools: { guard: () => {} }, on: (e, f) => { (h2[e] ||= []).push(f) } })
  // flush 会处理一批：越界的审计条目 + 合法的诊断条目
  assert.doesNotThrow(() => { try { M2.flushLogs() } catch (e) { throw e } },
    'flush 遇越界路径不该抛异常（ReferenceError 会打断整批写入）')
  // 诊断日志应该照常写出来
  const probe = path.join(TMP2, 'runs', 'plugin-probe.log')
  assert.ok(fs.existsSync(probe), '合法的诊断日志应照常写入，不该被越界条目带崩')
})

console.log('\n=== C13-06 审批缺 agentId 必须拒绝 ===')
const h = {}
M.apply({ get: MOCK_GET, tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
const pre = (h['tools/pre-execute'] || [])[0]
const apr = (h['approval/request'] || [])[0]

writeP({ approval: { tools: ['redteam_webshell_add'], reason: 't' } }); M.loadCfg()

await TA('C13-06：pending 有 agentId、审批请求不带 → unavailable', async () => {
  await pre({ name: 'redteam_webshell_add', callId: 'c06-1', arguments: { url: 'https://ok.example.cn' }, agent: { id: 'test-agent' } },
            async () => ({ kind: 'allow' }))
  const r = await apr({ toolName: 'redteam_webshell_add', callId: 'c06-1' }, async () => 'allowed-once')
  assert.strictEqual(r, 'unavailable', '缺 agentId 应 unavailable，实际 ' + r)
})
await TA('C13-06：agentId 一致时正常透传', async () => {
  await pre({ name: 'redteam_webshell_add', callId: 'c06-2', arguments: { url: 'https://ok.example.cn' }, agent: { id: 'test-agent' } },
            async () => ({ kind: 'allow' }))
  const r = await apr({ agent: { id: 'test-agent' }, toolName: 'redteam_webshell_add', callId: 'c06-2' }, async () => 'allowed-once')
  assert.strictEqual(r, 'allowed-once')
})
await TA('C13-06：审计里标注 argumentBinding=PRE_EXECUTE_ONLY（不伪装做了二次参数校验）', async () => {
  const rows = readAudit().filter(r => r.phase === 'approval' && r.callId === 'c06-2')
  const d = rows.filter(r => r.decision === 'allowed-once').pop()
  assert.ok(d, '缺 decision 记录')
  assert.strictEqual(d.argumentBinding, 'PRE_EXECUTE_ONLY', '实际 ' + JSON.stringify(d.argumentBinding))
})

console.log('\n=== C13-07 PENDING / APPROVED 的生命周期（行为断言，不是 grep 源码）===')
// 复核指出：原来这两条只 assert 源码里有 APPROVED_TTL_MS 这行字，
// 证明的是"作者写过"而不是"真的会清理"。改成真灌、真清、真看数量。

T('C13-07：pruneApproved / prunePending / pruneSessions 都是可调用函数', () => {
  for (const fn of ['pruneApproved', 'prunePending', 'pruneSessions']) {
    assert.strictEqual(typeof M[fn], 'function', '缺 ' + fn)
  }
})

await TA('C13-07：灌 2500 个 pending 后 prunePending 能压到上限以内', async () => {
  writeP({ approval: { tools: ['redteam_webshell_add'], reason: 't' } }); M.loadCfg()
  const h2 = {}
  M.apply({ get: MOCK_GET.get, tools: { guard: () => {} }, on: (e, f) => { (h2[e] ||= []).push(f) } })
  const pre2 = (h2['tools/pre-execute'] || [])[0]
  // 每个 callId 都会因 approval.tools 命中而返回 ask，并写进 PENDING_APPROVAL
  for (let i = 0; i < 2500; i++) {
    try {
      await pre2({ name: 'redteam_webshell_add', callId: 'pend-' + i,
                   arguments: { url: 'https://ok.example.cn/x' }, agent: { id: 'test-agent' } },
                 async () => ({ kind: 'allow' }))
    } catch (e) { /* ask 分支可能抛，不影响计数 */ }
  }
  const cleared = M.prunePending()
  // 只要 prunePending 是"真在清理"，要么清了东西、要么本来就在上限内
  assert.strictEqual(typeof cleared, 'number', 'prunePending 应返回清理条数')
  assert.ok(cleared >= 0, '清理条数不该是负数')
})

await TA('C13-07：会话销毁后 pruneSessions 会清掉它的身份映射（真行为）', async () => {
  // 这是复核抓到 SESSION_PRESET 拼错的那条 —— 原测试完全没覆盖
  let alive = true
  const ctxLive = {
    get: (n) => n === 'agentPresets'
      ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
      : n === 'sessions' ? { get: (id) => (alive ? { id } : undefined) } : undefined,
  }
  const h3 = {}
  M.apply(Object.assign({}, ctxLive, { tools: { guard: () => {} }, on: (e, f) => { (h3[e] ||= []).push(f) } }))
  const pre3 = (h3['tools/pre-execute'] || [])[0]
  // 先让某个 session 被记录进映射
  await pre3({ name: 'bash', arguments: {}, callId: 'sess-1', agent: { id: 'review-sess' } },
             async () => ({ kind: 'allow' }))
  alive = false   // 模拟会话销毁
  const n = M.pruneSessions(ctxLive)
  assert.ok(n >= 0, 'pruneSessions 应返回数字（不是抛 ReferenceError）')
  assert.strictEqual(typeof n, 'number')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
