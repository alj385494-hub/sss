import { fileURLToPath, pathToFileURL } from 'node:url'
/** V4 P1（C13-05 / C13-06 / C13-07 / C13-08 / C13-09）测试 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

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

let pass = 0, fail = 0
const T = (l, f) => { try { f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }
const TA = async (l, f) => { try { await f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }
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

console.log('\n=== C13-06 审批缺 agentId 必须拒绝 ===')
const h = {}
const MOCK_GET = (n) => n === 'agentPresets'
  ? { presetForSession: () => 'redteam-full', composedPreset: () => 'redteam-full' }
  : n === 'sessions' ? { get: () => ({ id: 'test-agent' }) } : undefined
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

console.log('\n=== C13-07 APPROVED_CALLS 有 TTL 与容量上限 ===')
T('C13-07：pruneApproved 存在且可调用', () => {
  assert.strictEqual(typeof M.pruneApproved, 'function')
  M.pruneApproved()
})
T('C13-07：源码里有 TTL 与容量常量', () => {
  const src = fs.readFileSync(path.join(process.cwd(), 'runs/plugins/dsh-tool-guardrail/lib/index.js'), 'utf8')
  assert.ok(/APPROVED_TTL_MS\s*=/.test(src), '缺 TTL')
  assert.ok(/APPROVED_MAX\s*=/.test(src), '缺容量上限')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
