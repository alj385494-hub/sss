---
name: severity-calibration
description: 【口径】危害校准：从 HackerOne 公开披露的真实案例反推"什么算漏洞"。六种被收录的模式（都有明确受害者）、对照我们在补天被打回的形态、以及三个写报告前的自检问句。判"这条到底算不算"时加载
whenToUse: 判定一条发现是否值得写报告时；被审核以"无实际危害"驳回后复盘时；给一批发现排序时；与 AGENTS §29 危害门槛配套使用
role: plan
enabled: true
---

# 危害校准：HackerOne 收录 vs 我们被打回的

> 样本：2026-11-15 抓取 HackerOne Hacktivity「Disclosed」按最新活动排序的前 25 条。
> 用途：给 `AGENTS.md` §29 危害门槛提供**外部权威参照**——不是我们的自定标准，是龙头平台的实际收录口径。

## 一、被收录的六种模式（每一种都有明确受害者）

| # | 模式 | 样本 | 受害者是谁 | 后果 |
|---|---|---|---|---|
| 1 | **跨主体越权（IDOR / 访问控制绕过）** | Revive Adserver「Cross-agency disclosure in website listing」Medium；「Access control bypass due to request precedence」**High** | **另一个机构/租户** | 读到别人的投放数据、改别人配置 |
| 2 | **存储型 / 跨账号 XSS** | Basecamp「Cross-account stored XSS → persistent administrator takeover」；Revive「Stored XSS in report date selection」 | **其他用户、管理员** | 在别人浏览器里执行 → 接管账号 |
| 3 | **缓存错配（Cache-Control 无 Vary: Cookie）** | Basecamp「Public board pages served `Cache-Control: public` with no `Vary: Cookie`, signed-in visitor's response cached at edge and returned to everyone」 | **已登录用户** | A 的私有页面被发给陌生人 |
| 4 | **权限提升** | Weblate「Privilege escalation via unfiltered role restoration in project backup import」 | 系统本身 | 低权限 → 高权限 |
| 5 | **能读库 / 能执行的注入** | Revive「Blind SQL injection due to request precedence」 | 数据库 | 能读库内容 |
| 6 | **绕过防护机制导致能力扩大** | Weblate「Anonymous API Rate Limit Bypass via X-Forwarded-For」**Medium**；PortSwigger「Burp 本地资源限制绕过 via `$id` rebasing」 | 服务方 | 能刷超过配额的请求 / 能读本不该读的本地文件 |

补充两类，容易被误当成"不算"（我第一版漏了）：

| # | 模式 | 样本 | 受害者 | 为什么算 |
|---|---|---|---|---|
| 7 | **暴露他人标识信息** | Weblate「Anonymous Translation Suggestion **IP Address Exposure** Through Change API」 | **提交内容的其他用户** | 泄露的是**别人的** IP（可定位到人），不是自己的、也不是公开的 |
| 8 | **CSRF（能改关键状态）** | Revive「CSRF in tracker invocation page」**Medium** | 被诱导点击的已登录用户 | 能替受害者**改配置/投放规则** → 有实际后果 |

> 另：`Formula injection in conversion tracking report export`（Code Injection, Medium）——
> 受害者是**打开导出文件的运营人员**，在 Excel 里打开时执行。

**这两条修正了两个我写错的判据**：
- `web-cors-csrf` 里"CSRF 多数被忽略"说得太绝对 —— **能改关键状态、受害者是已登录用户的 CSRF 是 Medium**；
- "信息泄露"不限于业务数据 —— **泄露他人 IP/邮箱/账号标识**同样成立（关键是"他人的"，不是"自己的"）。

## 二、被标成 Informative 的（等于不收录）—— 与我们的失败完全同构

| 样本 | 为什么是 Informative |
|---|---|
| Shopify「Unauthenticated UCP/MCP catalog access on a **password-protected dev store**」 | 只是"能访问"，**没证明拿到非公开内容**；dev store 本身就是测试环境 |

对照我们被打回的（都在 `runs/<靶标>/reports/*已撤稿*`）：
- A2 未授权附件 → 只能读 `Setting$WebSite_*`（网站 logo/背景）→ **读到公开素材**
- A1 令牌签发 → 签出来但**任何端点都不接受**
- C1 WebConfig → 13 项业务策略 + 字符黑名单，**敏感正则 0 命中**
- C2 WebPlus → `_redirect` 恒 302/0 字节，**不返正文**
- C3 CAS tenant → 292B 全是 logo 与主题开关
- QF 某SaaS平台 → 13 字段全是 H5 必发的前端配置
- Landray EKP → **换出口后证伪**（后端不读 `file` 参数）

**共同点：全部没有"受害者"** —— 读到的是自己的、公开的、或根本不存在的。

## 三、判据：写报告前必答的三个问句

```
Q1 受害者是谁？          → 答不出具体的人/机构/系统 → 不成立
                          （"另一个租户""已登录用户""管理员"才叫受害者）
Q2 他失去了什么？        → 数据？权限？会话？钱？时间？
                          （"知道了接口存在""知道了算法"不算失去）
Q3 我要做几步才能拿到？  → 步数越多价值越低；1 步能拿到别人数据的才是真洞
```

三条全过 → 写报告；任一条答不出 → **不写**，但要留否定证据链。

## 四、我们缺的方向（按"不需要账号就能打"排序）

| 方向 | 为什么值得打 | 怎么验（不需账号） |
|---|---|---|
| **缓存错配** | HackerOne 明确收录（Basecamp 那条）；教育/医疗系统大量用 CDN | 看响应头：`Cache-Control: public` 且**无 `Vary: Cookie``；再验证"带 Cookie 与不带 Cookie 的 URL 返回同一份缓存" |
| **跨主体 IDOR** | 平台中危口径直接对应"越权访问" | 同一接口换业务键（机构 id / 用户 id / 订单号），对比两个不同主体的返回 |
| **存储型 XSS** | 存储型有受害者；反射型多数被忽略 | 找"用户输入会被别人看到"的地方（留言、工单、审批备注、群公告） |
| **CSV/公式注入** | 导出报表时执行，受害者明确 | 找导出功能，看用户可控字段是否未转义 `=`/`+`/`@` 开头 |
| **限流绕过** | 能扩大实际能力就算（Medium 有先例） | 换 `X-Forwarded-For` / `X-Real-IP` / 大小写用户名，看是否进入不同配额桶 |

## 五、常见误判（我踩过的）

| 现象 | 错误结论 | 正确判据 |
|---|---|---|
| 接口无 Cookie 返回 200 和一堆字段 | 未授权访问 | 字段是不是**公开配置**？能不能**在正常页面拿到**？能 → 不算 |
| 签发了令牌/票据 | 认证缺陷 | 它**能不能换到会话/数据/操作**？换不到 → 物料，不是权限 |
| 换出口后 WAF 放行 | 漏洞存在 | **后端读没读这个参数**？无害值同体 → 不存在（见 `field-pitfalls` 七之二） |
| 跨站/跨 vhost 能取到内容 | 越权 | 内容**是不是本来就公开**？同一篇文章换个入口进来，零增量 |
| 泄露内部主机名/IP/版本号 | 信息泄露 | 平台忽略项（"无法直接利用的数据"） |

## 六、与 §29 的关系

`AGENTS.md` §29 是**规则**（拿不到别人拿不到的东西就不算），本技能是**校准器**（拿真实收录案例告诉你那条线画在哪）。
判据冲突时以 §29 为准；本技能用于说服自己"这条到底算不算"。

> **样本说明（如实）**：2026-11-15 抓取 HackerOne Hacktivity「Disclosed」按最新活动排序，**共产出 25 条**（分两次提取：20 + 5）。
> 其中 **16 条来自 Revive Adserver 同一产品**（XSS/IDOR/CSRF 反复命中），另有 2 条 WordPress XSS、2 条 Node.js 内核/内存类；
> **去重后约 9 种不同漏洞模式**，本文归为 8 类（含补的第 7、8 类）。样本窄、偏开源产品，**不是全行业分布**，结论需后续抓取更多样本校准。
> 抓取方式：`browser_open` 打开该页 → `browser_eval` 从 `a[href*="/reports/"]` 的父容器提取标题/摘要/类型/等级。
> 数据来源：`https://hackerone.com/hacktivity/overview?queryString=disclosed%3Atrue`
> 后续可在结项时重新抓取校准，样本越大越准。

---

# 附：Critical 100 条实证分布（2024-01 ~ 2026-12）

> 2026-11-15 抽样：`disclosed:true AND severity_rating:critical`，按最新活动排序取前 100 条。
> 平台全量公开披露 12,757 条，其中 critical 1,011 条（7.9%）——本样本占 critical 的约 10%。

## 一、CWE 分布（43 种，Top 12）

| CWE | 条数 | | CWE | 条数 |
|---|---|---|---|---|
| SQL Injection | 13 | | Privilege Escalation | 3 |
| Improper Access Control | 11 | | Insecure Direct Object Reference | 3 |
| （未标） | 9 | | Improper Authentication | 2 |
| Information Disclosure | 4 | | Stack Overflow / Use After Free | 2 / 2 |
| Path Traversal | 4 | | Deserialization / Command Injection | 2 / 2 |
| Code Injection | 4 | | Stored XSS / Cleartext Storage | 2 / 2 |
| SSRF | 4 | | CRLF Injection / Memory Corruption | 2 / 2 |

**读法**：critical 里 **SQLi + 访问控制 + 信息泄露 + 路径穿越 + 代码执行 + SSRF 六类占了 2/3**。
其余是库/内核级内存漏洞（curl、MariaDB、Node），不是我们能打的类型。

## 二、critical 的三大母题（100 条几乎全落在里面）

### 母题 1：账号接管（Account Takeover，ATO）——出现 ≥10 次
典型：
- `0-Click Account Takeover via Password Reset`（Remitly）
- `Account Takeover in Password Reset Function`（Mars）
- `Account Takeover via Password Reset without user interactions`（GitLab）
- `Ability to Add and Verify Uncontrolled Mobile Numbers Leading to ATO`（MTN）
- `Authentication Token Theft via Open Redirect in Callback URL Parameter`（Lemlist）★
- `1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation`（Khan Academy）★
- `Full Admin Takeover … 292 Users`（JFrog）
- `Unauthorized access to PII leads to Administrator account Takeover`（MTN）

**★ 这两条直接推翻了一个旧判据**：见下节。

### 母题 2：PII / 他人数据大规模泄露 —— 出现 ≥8 次
- `Mass PII Exposure: 120,000+ Consumer Email Addresses Leaked via Author Enumeration`
- `Air Force candidate PII + recruitment chat logs accessible via BAC/IDOR`
- `ASBS viewing other soldiers PII/Board/Board Voters`
- `[Critical Data Breach] Exposure of PII Data Leak via API Response`
- `Directory listing … disclosing names and emails, widespread (thousands of records)`
- `[Critical] Unauthorized Cross-Tenant Data Access`（Stripo）

**共同点**：不是"能访问接口"，是**看到了具体别人的姓名/邮箱/聊天记录**，而且给得出量级（120,000+ / thousands）。

### 母题 3：能执行 / 能读文件 / 能取库 —— 出现 ≥20 次
- `Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument ($where)`
- `Launchpad file read leaks production keys`（Basecamp）
- `Author → arbitrary file deletion anywhere on disk (site takeover)`
- `Unauthenticated reading of every file via livechat auth and predicting MongoDB ObjectId()`
- `DNN - Unrestricted Arbitrary File Upload`
- `GlobalProtect - OS Command Injection`
- `Complete authentication bypass to admin permissions`（SQLi）
- `Server Full Exposure with Database Credentials`（目录列举）

## 三、必须修正的判据

### ★ 修正 1：开放重定向在"回调链上"就不是忽略项

平台忽略清单里写「url 跳转」被忽略，但 HackerOne 上：
`Authentication Token Theft via **Open Redirect** in Callback URL Parameter` → **critical**，
`1-Click Account Takeover via **Open Redirect** through Regex Bypass` → **critical**。

**分界线**：跳转目标能不能**携带凭据**（token / ticket / code / SAMLResponse / JWT）？

| 情形 | 判定 |
|---|---|
| 纯跳转，不带任何凭据 | 忽略项（普通开放重定向） |
| 跳转 URL 会**附上 token/ticket/code**（OAuth `redirect_uri`、CAS `service`、SAML ACS、密码重置链接） | **账号接管，critical/高危** |

**这直接影响我们撤掉的那条**：东北师大 CAS `service` 白名单前缀绕过——
当时因为"缺账号无法证明 ticket 泄露"判成开放重定向；按本节，它的**性质是 ATO**，
只是取证缺一环（需 1 个账号观测登录后 Location 是否带 `?ticket=ST-…`）。**攒到账号就该回头打。**

### ★ 修正 2：限流弱 / IP 暴露 / 目录列举，单独也能上 critical
- `Weak Rate Limiting Controls in the LOGIN page` → 收录（配合爆破）
- `Anonymous Translation Suggestion IP Address Exposure` → 收录
- `Directory listing … names and emails, thousands of records` → **critical**（因为量级）

**判据**：不是"这个类型算不算"，而是**"它导致别人失去什么、涉及多少人"**。

## 四、我们的差距（照这 100 条回看被撤的 7 份）

| 我们撤掉的 | 100 条里最接近的 | 差在哪 |
|---|---|---|
| A2 未授权附件（读到登录页背景图） | `Mass PII Exposure 120,000+ emails` | 他们读到**别人**的邮箱，我们读到**公开素材** |
| A1 makeJwt（签发但被拒） | `Unrestricted Arbitrary File Upload` | 他们的产出**能用**，我们的令牌**不被接受** |
| C1 WebConfig（13 项策略） | `Server Full Exposure with Database Credentials` | 他们拿到 **DB 凭据**，我们拿到**开关和黑名单** |
| C2 WebPlus（302/0B） | `Unauthenticated reading of every file` | 他们**读到文件内容**，我们只看到**跳转** |
| C3 CAS tenant（292B branding） | `Cross-Tenant Data Access` | 他们**跨租户拿数据**，我们拿 **logo** |
| QF 某SaaS平台（13 个前端配置） | `Authentication Token Theft via Open Redirect` | 他们偷 **token**，我们拿 **appId + 现场签名**（前端必有） |
| Landray EKP（换出口后证伪） | `Launchpad file read leaks production keys` | 他们**读到密钥**，我们的后端**根本不读 file 参数** |

**一句话**：我们全部停在"能访问/能看到"，没有一条走到"拿到别人的东西/能用它做事"。

## 五、下一步该打的（按命中概率 × 成本）

| 优先 | 方向 | 为什么 | 怎么开始 |
|---|---|---|---|
| **1** | **密码重置 / 手机号验证 / 换绑 的绕过** | ATO 是 critical 第一母题；不需要已有账号 | 走完注册-找回流程，看 token 是否可猜、链接是否可重放、验证码是否绑定会话 |
| **2** | **OAuth/CAS/SAML 回调链的参数注入** | 上面两条 critical 都是这个 | 看 `redirect_uri`/`service`/`RelayState` 能否指外域、是否带凭据回跳 |
| **3** | **跨租户/跨用户 IDOR** | 有具体受害者，平台中危起 | 同接口换主体 ID，两个主体对比 |
| **4** | **目录列举 + 备份文件** | 一条能出 DB 凭据就 critical | `/.git/`、`/backup/`、`/db.sql`、`/WEB-INF/`、`/uploads/` 列目录 |
| **5** | **缓存错配（`Cache-Control` 无 `Vary: Cookie`）** | 已知收录；不需要账号 | 看响应头 + 对比带/不带 Cookie 的同一 URL |

> 抓取与复现方法：`browser_open` 打开 Hacktivity → `browser_eval` 拦截 `/graphql` 响应拿 `total_count` 与 `nodes`；
> 分页用 `variables.from` 递增；`disclosed:true` 的全量会被截断在 10000（ES `max_result_window`），需按年份切片累加。

---

# 附二：账号枚举的定级阶梯（2026-11-15 实战，化龙巷）

账号枚举是最容易被高估/低估的一类。**判据不在"能不能枚举"，而在"产出是什么"**。

## 三档

| 档 | 条件 | 案例 |
|---|---|---|
| **low** | 只能判"存在/不存在"，**有频控**、不可批量、响应里无附加信息 | 单次 `emailCheck` 返回 true/false |
| **medium** | ①**无任何频控**（压测 30/30 通过，≥2.5 req/s 持续）+ ②双向 oracle 逐字节稳定 + ③**已注册号额外吐出凭据**（token/uid/昵称） | 化龙巷：`sendYzm` 对已注册手机号**直接返回该账号找回 token**（32 位 hex，前端 `findpwd.js:129` 确认为 `token` 域值） |
| **critical** | 输入是**非 PII 空间**（自增 id / 短 id / 用户名），产出是 **PII 本体**（邮箱/手机/实名），且可上规模 | HackerOne：`Mass PII Exposure: 120,000+ emails via **Author Enumeration**` |

## 两条关键判据

**① 输入空间决定上限**
- 输入是**自增 id / 短数字 / 用户名** → 攻击者不知道受害者是谁也能扫 → 可升级到 PII 级
- 输入是**邮箱/手机号**（必须先知）→ 只能"验证已知值" → **上限是 medium**，套不上 critical

**② 产出里有没有"能用的东西"**
- 只有布尔 → low/medium（看有无频控）
- 返回 **token / uid / 昵称 / 注册时间** → 按凭据价值定级；**token 若能换会话或改密 → 直接 critical**

## 化龙巷实例（medium 的确证方式）

```
POST /pwd/sendYzm  {mobile:<已注册>}  → 200 / 56B / {"status":true,"msg":"034bec4c…(32位hex)"}
POST /pwd/sendYzm  {mobile:<未注册>}  → 200 / 161B / {"status":false,"msg":"该手机号未绑定任何账号"}
GET  /pwd/emailCheck?email=<未注册>   → 200 / 79B  / {"status":false,…}
GET  /pwd/emailCheck?email=<已注册>   → 200 / 24B  / {"status":true,"msg":""}
30/30 压测 0.3s 间隔零阻力；响应头无 Retry-After / X-RateLimit
```

**为什么不升 critical**：响应里没有 uid / nickname / 注册时间（邮箱侧正例仅 24B 空 msg），
产出是"布尔 + 一个未证可用的 token"，不是他人数据本体。

## 升 ATO 只差的那一步（验证方法留档）

**问：`setPwdFromMobile` 服务端到底校验不校验 `yzm`？**
- 前端强制先过 `checkYzm`，但那是**客户端门**，curl 可跳过直发
- 若服务端也不校验 `yzm` → 知道手机号 → 取 token → 直接改密 = **ATO**
- 验证必须用**自己注册绑定的测试号**，因为放行就等于改掉密码（他人账号是红线）

**判据记下来**：遇到"找回流程返回 token"，先做静态还原确认**字段集**（mobile/yzm/token 是否三者同行），
再用自己可控账号做**一次**错码提交：被拒 → 停在 medium；放行 → critical。
