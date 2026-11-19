/**
 * dsh-tool-guardrail 规则单测 —— 不需要 DSH、不需要重启。
 * 直接 import 插件的 evaluate()，用模拟的 exec 对象验证判定逻辑。
 *
 * 覆盖：放行 / 工具黑名单 / 按 agent 拒绝 / 参数上限 / 工具+参数条件 / observe 模式不拦
 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

// 不让单测污染生产日志：把工作区指到 runs/tmp 下
const TMP = path.join(process.cwd(), 'runs', 'tmp', 'guardrail-test-ws')
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
for (const f of ['guardrail-policy.json', 'scope.json']) {
  const src = path.join(process.cwd(), 'runs', 'tools', f)
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(TMP, 'runs', 'tools', f))
}
process.env.GUARDRAIL_WS = TMP

const P = 'file:///C:/Users/admin/Documents/deepseek-harness/default-workspace/runs/plugins/dsh-tool-guardrail/lib/index.js'
const { evaluate, loadCfg, apply } = await import(P)

const cfg = loadCfg().cfg   // v1.0 起 loadCfg 返回 {cfg,error,fresh}
let pass = 0, fail = 0
async function t(label, fn) {
  try { await fn(); console.log('  ✅', label); pass++ }
  catch (e) { console.log('  ❌', label, '→', e.message); fail++ }
}

console.log(`配置：enabled=${cfg.enabled} mode=${cfg.mode} agents=${Object.keys(cfg.agents).length} argMax=${Object.keys(cfg.argMax).length}\n`)

// ① 正常工具应放行
await t('普通工具（redteam_asset_query）→ 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: { limit: 50 } }, cfg), null)
})

// ② argMax：limit 超 1000 应拒绝
await t('limit=5000 超上限 1000 → 拒绝', () => {
  const v = evaluate({ name: 'redteam_asset_query', arguments: { limit: 5000 } }, cfg)
  assert.ok(v, '应为拒绝，实际放行')
  assert.strictEqual(v.rule, 'argMax')
  assert.strictEqual(v.matched, 'limit')
})
await t('limit=999 未超上限 → 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: { limit: 999 } }, cfg), null)
})
await t('limit 是数字字符串 "5000" → v1.0 起按数字处理并拒绝（P1-01）', () => {
  const v = evaluate({ name: 'x', arguments: { limit: '5000' } }, cfg)
  assert.ok(v && v.rule === 'argMax', '数字字符串应被抓到')
})
await t('limit 是非数字字符串 → 不误判', () => {
  assert.strictEqual(evaluate({ name: 'x', arguments: { limit: 'abc' } }, cfg), null)
})

// ③ argDeny：redteam_data_proof.row_count > 50000
await t('data_proof row_count=100000 → 拒绝（疑似批量导出）', () => {
  const v = evaluate({ name: 'redteam_data_proof', arguments: { row_count: 100000 } }, cfg)
  assert.ok(v, '应为拒绝')
  assert.strictEqual(v.rule, 'argDeny')
})
await t('data_proof row_count=12000 → 放行（12000 < 50000）', () => {
  assert.strictEqual(evaluate({ name: 'redteam_data_proof', arguments: { row_count: 12000 } }, cfg), null)
})

// ④ 按 agent 拒绝：身份串里含 recon，调 redteam_score_hit
await t('agent 身份=redteam-worker-recon + 调 redteam_score_hit → 拒绝（走 presetId）', () => {
  const ctxMock = { get: (n) => n === 'agentPresets' ? { presetForSession: () => 'redteam-worker-recon', composedPreset: () => 'redteam-worker-recon' }
                                         : n === 'sessions' ? { get: () => ({ id: 's' }) } : undefined }
  const v = evaluate({ name: 'redteam_score_hit', arguments: {}, agent: { id: 'sess-x' } }, cfg, ctxMock)
  assert.ok(v, '应为拒绝，说明 presetId 没匹配上')
  assert.strictEqual(v.rule, 'agentDeny')
})
await t('agent 含 recon + 调 redteam_asset_query → 放行（不在 deny 列表）', () => {
  const exec = {
    name: 'redteam_asset_query',
    arguments: {},
    agent: { options: { preset: 'redteam-worker-recon' } },
  }
  assert.strictEqual(evaluate(exec, cfg), null)
})
await t('agent 不含 recon（vuln-scan）+ 调 redteam_score_hit → 放行', () => {
  const exec = {
    name: 'redteam_score_hit',
    arguments: {},
    agent: { options: { preset: 'redteam-worker-vuln-scan' } },
  }
  assert.strictEqual(evaluate(exec, cfg), null)
})
await t('agent 为空的 exec 不崩 → 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: {} }, cfg), null)
  assert.strictEqual(evaluate({}, cfg), null)
})

// ⑤ toolDeny（配置里目前是空对象，临时注入试一下）
await t('toolDeny 命中 → 拒绝', () => {
  const c2 = { ...cfg, toolDeny: { danger_tool: '测试用无条件禁止' } }
  const v = evaluate({ name: 'danger_tool', arguments: {} }, c2)
  assert.ok(v)
  assert.strictEqual(v.rule, 'toolDeny')
})

// ⑥ 通过真实 apply 路径验证：mock ctx，确认 guard 被注册且 observe 模式不拦
await t('apply 注册了 pre-execute，observe 模式放行', async () => {
  const guards = []
  const hooks = {}
  const mockCtx = {
    tools: { guard: (fn) => guards.push(fn) },
    on: (ev, fn) => { (hooks[ev] ||= []).push(fn) },
  }
  apply(mockCtx)
  // v1.0 移除了 ctx.tools.guard（实测收不到 agent 调用），真正的拦截点是 pre-execute
  assert.ok((hooks['tools/pre-execute'] || []).length >= 1, 'pre-execute 没注册上')
  const pre = hooks['tools/pre-execute'][0]
  let called = false
  const ret = await pre({ name: 'x', arguments: { limit: 999999 }, agent: { options: { preset: 'recon' } } },
                        async () => { called = true; return { kind: 'allow' } })
  assert.ok(called, 'observe 模式应放行')
  assert.strictEqual(ret.kind, 'allow')
  assert.ok(hooks['tools/result'], 'tools/result 钩子没注册')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
