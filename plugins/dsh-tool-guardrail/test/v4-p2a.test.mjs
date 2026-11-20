import { fileURLToPath, pathToFileURL } from 'node:url'
/** V4 P2-a（C13-14 / C13-15 / C13-16 / C13-17）测试 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v4-p2a-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
// C13-18：用 import.meta.url 定位插件，不依赖 process.cwd() 或绝对路径
const HERE = path.dirname(fileURLToPath(import.meta.url))
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const M = await import(P + '?v=' + Date.now())
const PLUGIN = path.resolve(HERE, '..')

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
console.log('\n=== C13-14 脱敏覆盖 ===')
const RD = (v) => JSON.stringify(M.redactValue(v))
const cases = [
  ['x-api-key 连字符', { 'x-api-key': 'abcdef' }],
  ['client-secret', { 'client-secret': 'shhh' }],
  ['customCredential 驼峰', { customCredential: 'v' }],
  ['accessToken 驼峰', { accessToken: 'v' }],
  ['private-key', { 'private-key': '-----BEGIN RSA PRIVATE KEY-----' }],
  ['未知字段名的长凭据', { mystery: 'AbCdEf0123456789+/XYZabcdefghijklmn' }],
  ['顶层 JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'],
  ['PEM 私钥块', '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----'],
]
for (const [label, v] of cases) {
  T(`C13-14：${label} → 已脱敏`, () => {
    const r = RD(v)
    assert.ok(r.includes('REDACTED'), '没脱敏: ' + r)
  })
}
T('C13-14：URL 查询参数里的 token 脱敏、其他参数保留', () => {
  const r = RD({ url: 'https://a.com/x?token=abc&page=2' })
  assert.ok(r.includes('token=[REDACTED]'), r)
  assert.ok(r.includes('page=2'), '普通参数不该被脱敏: ' + r)
})
T('C13-14：Bearer 头脱敏', () => {
  assert.ok(RD({ h: 'Bearer eyJhbGciOiJIUzI1NiJ9.x.y' }).includes('REDACTED'))
})
T('C13-14：普通值不误伤（name / count / 长 URL）', () => {
  const r = RD({ name: 'hello', count: 3, url: 'https://example.com/very/long/path/segment/here/ok/x' })
  assert.ok(r.includes('hello') && r.includes('3'), r)
  assert.ok(r.includes('example.com'), '长 URL 不该被整个脱敏: ' + r)
})
T('C13-14：数组里的长凭据也脱敏', () => {
  const r = RD({ keys: ['AbCdEf0123456789+/XYZabcdefghijklmn'] })
  assert.ok(r.includes('REDACTED'), r)
})

console.log('\n=== C13-15 apply 幂等 ===')
T('同一个 ctx 调两次 apply → 监听器数量不变', () => {
  const h = {}
  const ctx = { tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } }
  M.apply(ctx, {})
  const snap1 = Object.keys(h).map(k => k + ':' + h[k].length).sort().join(',')
  M.apply(ctx, {})
  const snap2 = Object.keys(h).map(k => k + ':' + h[k].length).sort().join(',')
  assert.strictEqual(snap1, snap2, `重复注册了\n1: ${snap1}\n2: ${snap2}`)
})
T('重复 apply 会明确告警（不静默）', () => {
  const src = fs.readFileSync(path.join(PLUGIN, 'lib/index.js'), 'utf8')
  assert.ok(src.includes('重复 apply 被忽略'), '应有明确告警')
  assert.ok(src.includes('_appliedCtxs'), '应有 WeakSet 记号')
})

console.log('\n=== C13-16 peerDependencies 不用通配符 ===')
T('peerDeps 是版本范围，不是 *', () => {
  const d = JSON.parse(fs.readFileSync(path.join(PLUGIN, 'package.json'), 'utf8'))
  const pd = d.peerDependencies || {}
  assert.ok(Object.keys(pd).length > 0, '缺 peerDependencies')
  for (const [k, v] of Object.entries(pd)) {
    assert.notStrictEqual(v, '*', `${k} 仍是通配符`)
    assert.ok(/[<>=^~]|\d/.test(v), `${k} 没有版本约束: ${v}`)
  }
})
T('cordis 与 dsh-tools 都有约束', () => {
  const d = JSON.parse(fs.readFileSync(path.join(PLUGIN, 'package.json'), 'utf8'))
  assert.ok(d.peerDependencies['@deepseek-ai/cordis'], '缺 cordis')
  assert.ok(d.peerDependencies['@deepseek-ai/dsh-tools'], '缺 dsh-tools')
})

console.log('\n=== C13-17 发布防误操作 ===')
T('publishConfig 指向不可发布的 registry', () => {
  const d = JSON.parse(fs.readFileSync(path.join(PLUGIN, 'package.json'), 'utf8'))
  assert.ok(d.publishConfig && d.publishConfig.registry, '缺 publishConfig')
  assert.ok(/invalid|do-not-publish/.test(d.publishConfig.registry), '应指向无效 registry: ' + d.publishConfig.registry)
})
T('files 白名单限制发布内容', () => {
  const d = JSON.parse(fs.readFileSync(path.join(PLUGIN, 'package.json'), 'utf8'))
  assert.ok(Array.isArray(d.files) && d.files.length > 0, '缺 files')
  assert.ok(d.files.includes('lib'), 'files 应含 lib')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
