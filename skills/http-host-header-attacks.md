---
name: http-host-header-attacks
description: 【验证】Host 头攻击：Host/X-Forwarded-Host 未校验导致密码重置投毒、缓存污染、SSRF、路由绕过与虚拟主机越权，含"影响响应"与"仅回显"的区分
whenToUse: 应用读取 Host 头生成链接（密码重置邮件、跳转地址、绝对 URL），或前置反代按 Host 路由时
role: exploit
category: 验证
tags: [host-header, x-forwarded-host, password-reset-poisoning, vhost, 主机头]
enabled: true
---

# Host 头攻击

> 关键区分：**Host 头被回显**（低价值）vs **Host 头被用于生成链接/路由**（有价值）。

## 一、四种利用形态

### 1. 密码重置投毒（最高价值）

流程：请求重置 → 服务端生成 `https://<Host>/reset?token=xxx` → 发到受害者邮箱。

**若 Host 可控** → 链接指向攻击者域 → 受害者点击后 token 泄露。

```bash
curl -s -X POST "https://target/api/reset" \
  -H "Host: evil.example.com" \
  -H "Content-Type: application/json" -d '{"email":"attacker@example.com"}'
```
**判据**：收到的重置邮件里链接是 `evil.example.com`。

> 用**自己的邮箱/测试账号**验证，不用真实用户。

### 2. 缓存污染（与 `cache-poisoning-smuggling` 配合）

`X-Forwarded-Host` 被页面引用且不在缓存键里 → 污染他人页面里的绝对链接。

### 3. 路由/鉴权绕过

部分反代按 Host 决定转发与鉴权策略：
```bash
curl -s "https://target/admin" -H "Host: internal.example.com"
curl -s "https://target/admin" -H "X-Forwarded-Host: localhost"
```
**判据**：绕过 403 拿到内容。

### 4. SSRF / 绕 WAF

`X-Forwarded-For`/`X-Real-IP` 伪造成内网 IP，绕过 IP 白名单。

## 二、测试清单

| 头 | 用途 |
|---|---|
| `Host` | 主目标 |
| `X-Forwarded-Host` | 常见备用 |
| `X-Host`、`X-Forwarded-Server` | 部分框架 |
| `X-Original-URL`、`X-Rewrite-URL` | 路由覆盖 |
| `X-Forwarded-For`、`X-Real-IP`、`X-Client-IP` | IP 判定绕过 |
| `Forwarded: host=...` | RFC 7239 标准头 |

## 三、判定标准

| 结果 | 结论 |
|---|---|
| 重置邮件链接指向攻击者域 | ✅ 高（账号接管链） |
| 绕过鉴权拿到后台内容 | ✅ 高 |
| 页面绝对链接被换成攻击者域且缓存命中 | ✅ 中高 |
| Host 头只在响应里回显 | ❌ 不算（要证明被"使用"） |
| 反代直接返回 400 | ❌ 有校验 |

## 四、证据要求

1. 带篡改 Host 的请求 + 响应（证明影响点）
2. 密码重置：**收到的邮件截图**（链接必须是攻击者域）+ 说明用测试邮箱
3. 绕过：对比不带/带头的状态码与内容

## 五、失败判据

- 所有变体返回 400/403 且内容不变 → 有校验
- 只回显但不能造成任何影响 → 不算

## 六、边界

- 密码重置投毒**只用自己控制的邮箱/账号**
- 不向真实用户发送重置邮件
- 不实际使用窃取到的 token 登录他人账号

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 只看回显不看影响 | 回显不等于被使用 |
| 忽略反代的 Host 白名单 | 现代反代多数已校验 |
| 忘记试 `X-Forwarded-Host` | 有些只校验 `Host` 不管 XFH |
| 用真实用户邮箱测重置 | 越界 |
