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

const cfg = loadCfg()
let pass = 0, fail = 0
function t(label, fn) {
  try { fn(); console.log('  ✅', label); pass++ }
  catch (e) { console.log('  ❌', label, '→', e.message); fail++ }
}

console.log(`配置：enabled=${cfg.enabled} mode=${cfg.mode} agents=${Object.keys(cfg.agents).length} argMax=${Object.keys(cfg.argMax).length}\n`)

// ① 正常工具应放行
t('普通工具（redteam_asset_query）→ 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: { limit: 50 } }, cfg), null)
})

// ② argMax：limit 超 1000 应拒绝
t('limit=5000 超上限 1000 → 拒绝', () => {
  const v = evaluate({ name: 'redteam_asset_query', arguments: { limit: 5000 } }, cfg)
  assert.ok(v, '应为拒绝，实际放行')
  assert.strictEqual(v.rule, 'argMax')
  assert.strictEqual(v.matched, 'limit')
})
t('limit=999 未超上限 → 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: { limit: 999 } }, cfg), null)
})
t('limit 是字符串时不误判 → 放行', () => {
  assert.strictEqual(evaluate({ name: 'x', arguments: { limit: '5000' } }, cfg), null)
})

// ③ argDeny：redteam_data_proof.row_count > 50000
t('data_proof row_count=100000 → 拒绝（疑似批量导出）', () => {
  const v = evaluate({ name: 'redteam_data_proof', arguments: { row_count: 100000 } }, cfg)
  assert.ok(v, '应为拒绝')
  assert.strictEqual(v.rule, 'argDeny')
})
t('data_proof row_count=12000 → 放行（12000 < 50000）', () => {
  assert.strictEqual(evaluate({ name: 'redteam_data_proof', arguments: { row_count: 12000 } }, cfg), null)
})

// ④ 按 agent 拒绝：身份串里含 recon，调 redteam_score_hit
t('agent 含 recon + 调 redteam_score_hit → 拒绝', () => {
  const exec = {
    name: 'redteam_score_hit',
    arguments: {},
    agent: { id: 'agent-7', options: { preset: 'redteam-worker-recon' } },
  }
  const v = evaluate(exec, cfg)
  assert.ok(v, '应为拒绝，说明 agent 身份没匹配上')
  assert.strictEqual(v.rule, 'agentDeny')
  assert.strictEqual(v.matched, 'recon')
})
t('agent 含 recon + 调 redteam_asset_query → 放行（不在 deny 列表）', () => {
  const exec = {
    name: 'redteam_asset_query',
    arguments: {},
    agent: { options: { preset: 'redteam-worker-recon' } },
  }
  assert.strictEqual(evaluate(exec, cfg), null)
})
t('agent 不含 recon（vuln-scan）+ 调 redteam_score_hit → 放行', () => {
  const exec = {
    name: 'redteam_score_hit',
    arguments: {},
    agent: { options: { preset: 'redteam-worker-vuln-scan' } },
  }
  assert.strictEqual(evaluate(exec, cfg), null)
})
t('agent 为空的 exec 不崩 → 放行', () => {
  assert.strictEqual(evaluate({ name: 'redteam_asset_query', arguments: {} }, cfg), null)
  assert.strictEqual(evaluate({}, cfg), null)
})

// ⑤ toolDeny（配置里目前是空对象，临时注入试一下）
t('toolDeny 命中 → 拒绝', () => {
  const c2 = { ...cfg, toolDeny: { danger_tool: '测试用无条件禁止' } }
  const v = evaluate({ name: 'danger_tool', arguments: {} }, c2)
  assert.ok(v)
  assert.strictEqual(v.rule, 'toolDeny')
})

// ⑥ 通过真实 apply 路径验证：mock ctx，确认 guard 被注册且 observe 模式不拦
t('apply 注册了 guard，observe 模式对超限调用返回 undefined（只记录不拦）', () => {
  const guards = []
  const hooks = {}
  const mockCtx = {
    tools: { guard: (fn) => guards.push(fn) },
    on: (ev, fn) => { (hooks[ev] ||= []).push(fn) },
  }
  apply(mockCtx)
  assert.strictEqual(guards.length, 1, 'guard 没注册上')
  const ret = guards[0]({ name: 'x', arguments: { limit: 999999 }, agent: { options: { preset: 'recon' } } })
  assert.strictEqual(ret, undefined, `observe 模式不该拦，实际返回：${ret}`)
  assert.ok(hooks['tools/result'], 'tools/result 钩子没注册')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
