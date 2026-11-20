/** V4 P2 收尾（C13-24 / C13-25）测试 */
import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const TMP = path.join(os.tmpdir(), 'dsh-guardrail-p2c-' + process.pid)
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
const M = await import(pathToFileURL(path.resolve(HERE, '../lib/index.js')).href + '?v=' + Date.now())
const POL = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
const SCP = path.join(TMP, 'runs', 'tools', 'scope.json')
const PROBE = path.join(TMP, 'runs', 'plugin-probe.log')
fs.writeFileSync(POL, JSON.stringify({ enabled: true, mode: 'observe', agents: {}, argMax: {}, argDeny: [] }), 'utf8')
fs.writeFileSync(SCP, JSON.stringify({
  version: '1.0', authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains: [], ips: [], ipv6: [] },
}), 'utf8')
M.loadCfg(); M.loadScope()

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
console.log('\n=== C13-24 日志不记完整工作区路径 ===')
T('wsLabel 只返回「末段目录名#哈希」，不含完整路径', () => {
  const label = M.wsLabel('/srv/projects/secret-proj')
  assert.ok(label, '不该为 null')
  assert.ok(!label.includes('/srv'), '不含父级路径: ' + label)
  
  assert.ok(label.includes('secret-proj'), '应保留末段目录名便于识别: ' + label)
  assert.ok(/#[0-9a-f]{8}$/.test(label), '应带 8 位哈希: ' + label)
})
T('相同路径得到相同标签（可用于区分多工作区）', () => {
  assert.strictEqual(M.wsLabel('C:/a/b'), M.wsLabel('C:/a/b'))
})
T('不同路径得到不同哈希', () => {
  assert.notStrictEqual(M.wsLabel('C:/a/b'), M.wsLabel('C:/a/c'))
})
T('空路径返回 null', () => {
  assert.strictEqual(M.wsLabel(''), null)
  assert.strictEqual(M.wsLabel(null), null)
})
T('GUARDRAIL_DEBUG_WS=1 时返回完整路径（调试用）', () => {
  const before = process.env.GUARDRAIL_DEBUG_WS
  process.env.GUARDRAIL_DEBUG_WS = '1'
  try {
    assert.strictEqual(M.wsLabel('C:/tmp/x'), 'C:/tmp/x')
  } finally {
    if (before === undefined) delete process.env.GUARDRAIL_DEBUG_WS
    else process.env.GUARDRAIL_DEBUG_WS = before
  }
})
T('plugin-loaded 日志里 workspace 字段是标签不是绝对路径', () => {
  const h = {}
  M.apply({ get: () => undefined, tools: { guard: () => {} }, on: (e, f) => { (h[e] ||= []).push(f) } })
  try { M.flushLogs() } catch (e) {}
  assert.ok(fs.existsSync(PROBE), 'probe 日志没生成')
  const rows = fs.readFileSync(PROBE, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
  const lo = rows.filter((r) => r.tag === 'plugin-loaded').pop()
  assert.ok(lo, '缺 plugin-loaded 记录')
  const ws = String(lo.workspace || '')
  assert.ok(!/^[A-Za-z]:[\\/]/.test(ws), 'workspace 不该是盘符开头的绝对路径: ' + ws)
  assert.ok(ws.includes('#'), 'workspace 应是「名#哈希」形式: ' + ws)
})

console.log('\n=== C13-25 能力边界必须写明（不假装有网络控制）===')
T('C13-25 反向验证：代码里确实没有网络控制实现（只有声明）', () => {
  // 复核指出：原来这条只 grep 注释里有没有"DNS 解析""重定向"这些词，
  // 那证明的是"作者写了这段声明"，不是"确实没做网络控制"。
  // 反向验证：真去查有没有实际的控制实现，没有才算诚实。
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  const impl = [
    /execSync\([^)]*iptables/, /execSync\([^)]*nftables/,
    /spawn\([^)]*iptables/, /net\.connect\([^)]*socket/,
    /dns\.lookup\(/, /followRedirect/, /http\.request\(/
  ].filter((r) => r.test(src))
  assert.strictEqual(impl.length, 0,
    '声称"不做网络控制"却在代码里有这些实现: ' + impl.map(String).join(', '))
})

T('源码里有能力边界说明，且明确说"不能代替网络访问控制"', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  assert.ok(src.includes('C13-25'), '缺 C13-25 标注')
  assert.ok(/只能看到\*\*工具参数\*\*|只能看到工具参数/.test(src), '应说明只能看参数')
  assert.ok(src.includes('不能') && (src.includes('网络强制') || src.includes('网络访问控制')), '应明确说做不到网络强制')
  for (const k of ['DNS 解析', '重定向', '代理出口', 'shell 命令']) {
    assert.ok(src.includes(k), '应列出做不到的场景: ' + k)
  }
})
T('源码里明确 net_observe 是观测不是控制', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../lib/index.js'), 'utf8')
  assert.ok(/net_observe\.py\s*是\*\*观测\*\*/.test(src) || src.includes('是**观测**，不是控制'),
    '应说明 net_observe 只是观测')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
