import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
const TMP = path.join(process.cwd(), 'runs', 'tmp', 'g01-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
// C13-18：用 import.meta.url 定位插件，不依赖 process.cwd() 或绝对路径
const HERE = path.dirname(fileURLToPath(import.meta.url))
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const { evaluate, loadScope } = await import(P + '?v=' + Date.now())
const POLICY = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCOPE = path.join(TMP, 'runs', 'tools', 'scope.json')
fs.writeFileSync(POLICY, JSON.stringify({ enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }), 'utf8')


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
// scope 文件不存在
fs.rmSync(SCOPE, { force: true })
loadScope()
T('G-01：scope 文件缺失 + enforce + 受保护工具(redteam_webshell_add) → 拒绝', () => {
  const v = EV({ name: 'redteam_webshell_add', arguments: {} }, { enabled: true, mode: 'enforce' })
  assert.ok(v, '应拒绝，实际放行')
  assert.strictEqual(v.rule, 'scopeUnavailable')
})
T('G-01：scope 缺失 + enforce + 普通工具(bash) → 放行（不误伤）', () => {
  const v = EV({ name: 'bash', arguments: {} }, { enabled: true, mode: 'enforce' })
  assert.strictEqual(v, null, '普通工具不该被拦')
})
T('G-01：scope 缺失 + observe + 受保护工具 → 放行（observe 不拦）', () => {
  const v = EV({ name: 'redteam_webshell_add', arguments: {} }, { enabled: true, mode: 'observe' })
  assert.strictEqual(v, null)
})

// scope 损坏
fs.writeFileSync(SCOPE, '{ broken json', 'utf8')
loadScope()
T('G-01：scope JSON 损坏 + enforce + 受保护工具 → 拒绝', () => {
  const v = EV({ name: 'redteam_credential_add', arguments: {} }, { enabled: true, mode: 'enforce' })
  assert.ok(v && v.rule === 'scopeUnavailable', '实际: ' + JSON.stringify(v))
})

// scope 正常
fs.writeFileSync(SCOPE, JSON.stringify({
  allowUnlisted: false, allowLocal: false,
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] },
}), 'utf8')
loadScope()
T('G-01：scope 正常 + 授权内目标 → 放行', () => {
  const v = EV({ name: 'redteam_webshell_add', arguments: { url: 'https://ok.example.cn/x' } }, { enabled: true, mode: 'enforce' })
  assert.strictEqual(v, null)
})
T('G-01：scope 正常 + 域外目标 → outOfScope', () => {
  const v = EV({ name: 'redteam_webshell_add', arguments: { url: 'https://evil.example.org/x' } }, { enabled: true, mode: 'enforce' })
  assert.ok(v && v.rule === 'outOfScope', '实际: ' + JSON.stringify(v))
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
