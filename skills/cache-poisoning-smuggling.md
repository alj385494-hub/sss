---
name: cache-poisoning-smuggling
description: 【验证】缓存投毒与请求走私：用 unkeyed 头/参数判断缓存键、用 CL/TE 差分判断前端与后端解析不一致，判定"能否让缓存或后端处理我的走私请求"，含只读证明与停止点
whenToUse: 目标前置有 CDN/反代（响应头有 X-Cache/Via/Age），或怀疑前端与后端对请求边界解析不一致时
role: exploit
category: 验证
tags: [cache-poisoning, smuggling, cl-te, http-desync, 缓存投毒, 请求走私]
enabled: true
---

# 缓存投毒与请求走私

> 两者共同点：**利用前端与后端"理解不一致"**。
> 缓存投毒利用"缓存键算漏了某参数"；请求走私利用"body 边界算错了"。

## 一、缓存投毒：先判缓存键

### 步骤 1 · 确认有缓存
```bash
curl -sI "https://target/x" | grep -iE "x-cache|cf-cache|age|via|cdn"
```
`Age` 变大 / `X-Cache: HIT` → 有缓存。

### 步骤 2 · 找 unkeyed 输入

请求头里加一个随机值，看**响应是否变化但缓存键不变**：
```bash
# 基线
curl -sI "https://target/x" | grep -iE "^x-|^location"
# 加头
curl -sI "https://target/x" -H "X-Forwarded-Host: evil.example.com" | grep -iE "^x-|^location"
```
**候选 unkeyed 头**：`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Original-URL`、`X-Rewrite-URL`、`X-Host`、`X-Forwarded-Port`。

### 步骤 3 · 判定可利用
三个条件同时成立才算：
1. 该输入**影响响应**（如注入的 host 出现在页面/重定向 Location）
2. 该输入**不在缓存键里**（换一个 key 值请求，命中同一缓存条目）
3. 缓存**对他人可见**（其他用户拿到被污染的响应）

**证明方式（只读）**：
```bash
# 用带毒头的请求打一个唯一路径
curl -s "https://target/path?cb=uniq123" -H "X-Forwarded-Host: oob.example.com"
# 再不带毒头请求同一路径，看是否返回被污染的响应
curl -s "https://target/path?cb=uniq123"
```
**判据**：第二次请求（干净请求）返回了含 `oob.example.com` 的内容 → 投毒成功。

## 二、请求走私：CL/TE 差分

### 原理速查

| 组合 | 前端信任 | 后端信任 | 结果 |
|---|---|---|---|
| `CL` + `TE: chunked` | CL | TE | 走私 |
| `CL` + 混淆 TE（`chunked` 大小写/重复） | TE | CL | 走私 |
| 双 `Content-Length` 不同值 | 前者 | 后者 | 走私 |

### 检测（**必须用不会影响他人的方式**）

```bash
# 时间差法：走私一个会让后端等待的前缀到自身
# 用两次连续请求，比较耗时差
```

**危险提示**：走私测试一旦失手，**污染的是共享连接池，可能影响其他真实用户**。

**安全做法**：
1. 用**独立且可辨识的路径**（如 `/smuggle-test-<random>`）
2. 不做需要"让后端把请求挂起"的经典 CL.TE 探测（会占用后端连接）
3. 优先做**被动判断**：看是否有 `Transfer-Encoding` 与 `Content-Length` 同时出现、是否大小写混乱

## 三、判定标准

| 结果 | 结论 |
|---|---|
| 缓存投毒：干净请求返回被污染内容 | ✅ 高（影响所有用户） |
| 缓存投毒：只有自己看到 | ❌ 不算 |
| 走私：能稳定让后端把 A 请求的后半段当 B 请求处理 | ✅ 高（但影响面大，慎测） |
| 只有 CL/TE 都出现但无法证明走私 | ❌ 不算 |

## 四、证据要求

1. 缓存：`X-Cache`/`Age` 头 + 带毒请求 + 干净请求的响应对比
2. 走私：两次请求的完整原始报文 + 时序/响应差异
3. **必须写清影响范围**（是否影响其他用户）

## 五、失败判据

- 无 CDN/反代 → 无缓存投毒面
- 缓存键包含所有输入（换头就 MISS）→ 不可投毒
- CL/TE 校验严格（前端拒绝双头）→ 放弃走私

## 六、边界（红线，最重要）

| 禁止 | 原因 |
|---|---|
| 在生产做会挂起连接的走私探测 | 可能拖垮后端/影响真实用户 |
| 投毒一个真实用户会访问的路径 | 等于对他人投毒 |
| 用投毒挂 XSS/钓鱼 | 违法 |
| 反复触发 | 可能被 CDN 封 IP |

**只允许**：唯一路径上的最小证明 + 立即停止。

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 把"头回显"当投毒 | 要证明**缓存**且**对他人可见** |
| 用别人的真实路径测试 | 影响真实用户 |
| 忽略 CDN 的缓存规则 | 有的只缓存静态资源 |
| 走私测试后不清理 | 残留污染 |
