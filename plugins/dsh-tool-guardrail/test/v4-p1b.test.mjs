import { fileURLToPath, pathToFileURL } from 'node:url'
/** V4 P1 后段（C13-11 / C13-12 / C13-13）测试 */
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

const TMP = path.join(process.cwd(), 'runs', 'tmp', 'v4-p1b-test')
fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(path.join(TMP, 'runs', 'tools'), { recursive: true })
process.env.GUARDRAIL_WS = TMP
// C13-18：用 import.meta.url 定位插件，不依赖 process.cwd() 或绝对路径
const HERE = path.dirname(fileURLToPath(import.meta.url))
const P = pathToFileURL(path.resolve(HERE, '../lib/index.js')).href
const M = await import(P + '?v=' + Date.now())
const SCP = path.join(TMP, 'runs', 'tools', 'scope.json')
const POL = path.join(TMP, 'runs', 'tools', 'guardrail-policy.json')
fs.writeFileSync(POL, JSON.stringify({ enabled: true, mode: 'enforce', agents: {}, argMax: {}, argDeny: [] }), 'utf8')

let pass = 0, fail = 0
const T = (l, f) => { try { f(); console.log('  ✅', l); pass++ } catch (e) { console.log('  ❌', l, '→', e.message); fail++ } }

console.log('\n=== C13-12 域名匹配三态 ===')
T('exact：a.com 只匹配自己，不匹配子域', () => {
  const r = M.parseDomainRule({ name: 'a.com', match: 'exact' })
  assert.ok(M.domainRuleMatches('a.com', r))
  assert.ok(!M.domainRuleMatches('x.a.com', r), 'exact 不该匹配子域')
  assert.ok(!M.domainRuleMatches('x.y.a.com', r))
})
T('wildcard：*.a.com 匹配一级子域，不匹配 apex', () => {
  const r = M.parseDomainRule({ name: '*.a.com', match: 'wildcard' })
  assert.ok(M.domainRuleMatches('x.a.com', r))
  assert.ok(M.domainRuleMatches('x.y.a.com', r), '多级也算子域')
  assert.ok(!M.domainRuleMatches('a.com', r), 'wildcard 不该匹配 apex')
})
T('subdomain（默认）：a.com 覆盖自身与所有子域', () => {
  const r = M.parseDomainRule('a.com')
  assert.strictEqual(r.match, 'subdomain')
  assert.ok(M.domainRuleMatches('a.com', r))
  assert.ok(M.domainRuleMatches('x.a.com', r))
})
T('字符串写法等价旧行为（向后兼容）', () => {
  assert.strictEqual(M.parseDomainRule('b.com').match, 'subdomain')
})
T('大小写与尾部点号规范化', () => {
  assert.strictEqual(M.normDomain('A.COM.'), 'a.com')
})
T('IDNA：中文域名转 punycode', () => {
  const n = M.normDomain('测试.中国')
  assert.ok(n.startsWith('xn--'), '实际 ' + n)
})

console.log('\n=== C13-12 在 outOfScope 里的实际效果 ===')
const baseScope = (domains) => ({
  version: '1.0',
  authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
  targets: { domains, ips: [], ipv6: [] },
  serviceAllowlist: [], allowUnlisted: false, allowLocal: true,
})
const withScope = (sc) => { fs.writeFileSync(SCP, JSON.stringify(sc), 'utf8'); M.loadScope(); return M.loadScope().scope }

T('scope 配 exact → 子域被判越界', () => {
  const sc = withScope(baseScope([{ name: 'a.com', match: 'exact' }]))
  const r = M.outOfScope({ url: 'https://x.a.com/' }, sc)
  assert.ok(r.bad.length > 0, '子域应越界（exact 语义）')
})
T('scope 配 exact → apex 自己放行', () => {
  const sc = withScope(baseScope([{ name: 'a.com', match: 'exact' }]))
  assert.strictEqual(M.outOfScope({ url: 'https://a.com/' }, sc).bad.length, 0)
})
T('scope 配 wildcard → 子域放行、apex 越界', () => {
  const sc = withScope(baseScope([{ name: '*.a.com', match: 'wildcard' }]))
  assert.strictEqual(M.outOfScope({ url: 'https://x.a.com/' }, sc).bad.length, 0)
  assert.ok(M.outOfScope({ url: 'https://a.com/' }, sc).bad.length > 0, 'apex 应越界')
})
T('scope 配 subdomain → 子域放行（默认行为不变）', () => {
  const sc = withScope(baseScope([{ name: 'a.com', match: 'subdomain' }]))
  assert.strictEqual(M.outOfScope({ url: 'https://x.a.com/' }, sc).bad.length, 0)
})

console.log('\n=== C13-13 IPv6 CIDR ===')
T('2001:db8::1 在 2001:db8::/32 内', () => {
  assert.strictEqual(M.ipv6InCidr('2001:db8::1', '2001:db8::/32'), true)
})
T('2001:db9::1 不在 2001:db8::/32 内', () => {
  assert.strictEqual(M.ipv6InCidr('2001:db9::1', '2001:db8::/32'), false)
})
T('非法掩码 /129 拒绝', () => {
  assert.strictEqual(M.ipv6InCidr('2001:db8::1', '2001:db8::/129'), false)
})
T('非法掩码 /abc 拒绝', () => {
  assert.strictEqual(M.ipv6InCidr('2001:db8::1', '2001:db8::/abc'), false)
})
T('IPv4-mapped 形式可解析', () => {
  assert.strictEqual(M.ipv6InCidr('::ffff:<IP>', '::/0'), true)
})
T('/128 精确匹配', () => {
  assert.strictEqual(M.ipv6InCidr('2001:db8::1', '2001:db8::1/128'), true)
  assert.strictEqual(M.ipv6InCidr('2001:db8::2', '2001:db8::1/128'), false)
})
T('scope 配 IPv6 CIDR → 段内放行、段外越界', () => {
  const sc = withScope({
    version: '1.0', authorization: { status: 'active', expiresAt: '2030-01-01T00:00:00Z' },
    targets: { domains: [], ips: [], ipv6: ['2001:db8::/32'] },
    serviceAllowlist: [], allowUnlisted: false, allowLocal: false,
  })
  const inC = M.outOfScope({ ip: '2001:db8::5' }, sc)
  assert.ok(!inC.bad.length, '段内应放行，实际 ' + JSON.stringify(inC.bad))
  const outC = M.outOfScope({ ip: '2001:db9::5' }, sc)
  assert.ok(outC.bad.length > 0, '段外应越界')
})

console.log(`\n结果：${pass} 通过 / ${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
