---
name: tech-oauth-sso
description: 【验证】OAuth2 / OIDC / SSO 攻击面：redirect_uri 校验缺陷、state 缺失、code 复用、scope 提升、令牌泄露位置，以及 CAS/Shibboleth 类单点的常见弱点
whenToUse: 目标使用 OAuth2/OIDC 登录（authorize?client_id=&redirect_uri=）、CAS/Shibboleth 单点、或有多子系统共享登录态时
role: exploit
category: 验证
tags: [oauth, oidc, sso, cas, shibboleth, redirect-uri, 单点登录]
enabled: true
---

# OAuth2 / OIDC / SSO 攻击面

> SSO 的价值在于**一处缺陷影响所有接入系统**；但也因为标准实现成熟，多数配置是对的。
> 先看流程，再挑校验点。

## 一、先摸清流程

抓一次完整登录，记录：
1. `/authorize?client_id=...&redirect_uri=...&state=...&scope=...`
2. 跳转到 IdP 登录页 → 回调 `?code=...&state=...`
3. 用 code 换 token：`/token?code=...&client_secret=...`
4. 用 token 取用户：`/userinfo`

**把每一步的参数抄下来**，后面逐项打。

## 二、六个测试点（按命中率）

### 1. redirect_uri 校验缺陷（最高价值）

| 变体 | 说明 |
|---|---|
| 加子域 | `https://target.com.evil.com/cb` |
| 改路径 | `https://target.com/evil` |
| 加后缀 | `https://target.com/callback/../evil` |
| 参数污染 | `?redirect_uri=https://target.com/cb&redirect_uri=https://evil.com` |
| 编码绕过 | `https://target.com%2f@evil.com` |

**判据**：code 被发到**攻击者可控地址**。抓到 code 即成功（不需要换 token 就能证明）。

### 2. state 缺失 / 不校验

**判据**：删掉 `state` 或改成任意值，流程仍能完成 → 存在 CSRF 风险（价值中等）。

### 3. code 复用

**判据**：同一个 code 用两次仍能换 token（OAuth2 要求一次性）。

### 4. scope 提升

改 `scope=openid profile` 为 `scope=openid profile admin` 或加 `offline_access`。
**判据**：返回的 token 权限超出申请范围。

### 5. 令牌泄露位置

| 位置 | 风险 |
|---|---|
| URL 参数带 `access_token` | 会进 Referer/日志 |
| 前端 `localStorage` | XSS 可读 |
| `postMessage` 无 origin 校验 | 可跨域窃取 |

### 6. CAS / Shibboleth 专项

| 点 | 说明 |
|---|---|
| `/cas/serviceValidate?ticket=` | 票据是否可复用、是否校验 service 白名单 |
| `/idp/profile/SAML2/Redirect/SSO` | SAML 断言签名是否校验、是否接受未签名断言 |
| 默认页 | `Welcome to IdP Server` = 未配置，价值低 |

## 三、判定标准

| 结果 | 结论 |
|---|---|
| code 被发到攻击者域 | ✅ 高（认证绕过） |
| code 可复用 | ✅ 中 |
| state 不校验 + 可完成流程 | ✅ 中低 |
| scope 可越权提升 | ✅ 中高 |
| 只有默认页/版本号 | ❌ 不算 |

## 四、证据要求

1. 完整授权请求（含被篡改的 redirect_uri/scope）
2. 证明 code/token 被发到攻击者地址（用 OOB 或自建回调页截图）
3. 说明影响：能冒充谁、能访问哪些系统

## 五、失败判据

- redirect_uri 严格白名单且无绕过 → 放弃
- state 校验正常、code 一次性正常 → 放弃
- SAML 签名校验正常 → 放弃

## 六、边界

- **只用自己注册的 OAuth 应用/测试账号**
- 不实际窃取真实用户 code/token
- SAML 只验证"签名是否校验"，不伪造他人断言登录

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 把 `state` 缺失当高危 | 多数平台判中低 |
| 忽略 redirect_uri 白名单的严格匹配 | 现代实现多是精确匹配，难绕 |
| 忘记看 IdP 类型 | CAS/Shibboleth/OIDC 的测试点不同 |
| 用真实用户流程测试 | 会污染日志，用测试账号 |

---

## 八、取证陷阱：WAF 关键词拦截会伪装成"应用拒绝"（2026-11 实测）

测 `redirect_uri` 时，用**攻击者风格的域名**（如 `evil.example.com`）很可能被 WAF 按关键词拦掉，
返回 510/403，**看起来像"应用拒绝了跳转"，其实你根本没打到应用**。

**实测**：某目标 `redirect_uri=https://evil.example.com` → **510**；
换成中性域 `www.baidu.com` → 拿到真实的 **302 → /Error**（说明校验确实正常）。

> **规则**：排查 redirect_uri 时，**先用一个中性公网域名做对照组**。
> 若中性域也是 510 → 是 WAF 拦的，换测试值或换子域；
> 只有中性域能到达应用，才说明你在测应用本身的校验逻辑。

---

## 报错顺序本身就是结论（别把"没测到"写成"校验严格"）

`/oauth/authorize` 的校验有顺序（常见：response_type → client_id → redirect_uri）。
若任意 `client_id` 都返回 `invalid_client`，则 **redirect_uri 白名单永远到不了校验点**。

- 正确结论：「**到不了校验点，未测到**」（阻塞项）
- 错误结论：「redirect_uri 校验严格 / 无缺陷」（安全声明）

实测（2026-11-14 <客户域名> 开放平台）：`response_type` 缺参→`invalid_request`；`client_id` 乱填→`invalid_client`；
`redirect_uri` 没进入校验。
> 来源：RFC 6749 §<IP> 要求校验 redirect_uri；但校验发生在 client 校验**之后**是常见实现顺序，
> doorkeeper PR #1910 专门修「在认证资源所有者之前先校验 client」这一问题
> （https://github.com/doorkeeper-gem/doorkeeper/pull/1910 ）。故"到不了校验点"是可复现的工程现象，不是猜测。

