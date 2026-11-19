import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
const TMP = path.join(process.cwd(), 'runs', 'tmp', 'g01-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
const P = 'file:///' + path.join(process.cwd(), 'runs/plugins/dsh-tool-guardrail/lib/index.js').split(path.sep).join('/')
const { evaluate, loadScope } = await import(P + '?v=' + Date.now())
const POLICY = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCOPE = path.join(TMP, 'runs', 'tools', 'scope.json')
fs.writeFileSync(POLICY, JSON.stringify({ enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }), 'utf8')

let pass = 0, fail = 0
const T = (l, f) => { try { f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }

// scope 文件不存在
fs.rmSync(SCOPE, { force: true })
loadScope()
T('G-01：scope 文件缺失 + enforce + 受保护工具(redteam_webshell_add) → 拒绝', () => {
  const v = evaluate({ name: 'redteam_webshell_add', arguments: {} }, { enabled: true, mode: 'enforce' }, undefined)
  assert.ok(v, '应拒绝，实际放行')
  assert.strictEqual(v.rule, 'scopeUnavailable')
})
T('G-01：scope 缺失 + enforce + 普通工具(bash) → 放行（不误伤）', () => {
  const v = evaluate({ name: 'bash', arguments: {} }, { enabled: true, mode: 'enforce' }, undefined)
  assert.strictEqual(v, null, '普通工具不该被拦')
})
T('G-01：scope 缺失 + observe + 受保护工具 → 放行（observe 不拦）', () => {
  const v = evaluate({ name: 'redteam_webshell_add', arguments: {} }, { enabled: true, mode: 'observe' }, undefined)
  assert.strictEqual(v, null)
})

// scope 损坏
fs.writeFileSync(SCOPE, '{ broken json', 'utf8')
loadScope()
T('G-01：scope JSON 损坏 + enforce + 受保护工具 → 拒绝', () => {
  const v = evaluate({ name: 'redteam_credential_add', arguments: {} }, { enabled: true, mode: 'enforce' }, undefined)
  assert.ok(v && v.rule === 'scopeUnavailable', '实际: ' + JSON.stringify(v))
})

// scope 正常
fs.writeFileSync(SCOPE, JSON.stringify({
  allowUnlisted: false, allowLocal: false,
  targets: { domains: ['ok.example.cn'], ips: [], ipv6: [] },
}), 'utf8')
loadScope()
T('G-01：scope 正常 + 授权内目标 → 放行', () => {
  const v = evaluate({ name: 'redteam_webshell_add', arguments: { url: 'https://ok.example.cn/x' } }, { enabled: true, mode: 'enforce' }, undefined)
  assert.strictEqual(v, null)
})
T('G-01：scope 正常 + 域外目标 → outOfScope', () => {
  const v = evaluate({ name: 'redteam_webshell_add', arguments: { url: 'https://evil.example.org/x' } }, { enabled: true, mode: 'enforce' }, undefined)
  assert.ok(v && v.rule === 'outOfScope', '实际: ' + JSON.stringify(v))
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
