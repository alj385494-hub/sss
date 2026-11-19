---
name: web-graphql
description: 【验证】GraphQL 攻击面：内省拿全 schema、按 schema 找未授权字段与批量查询、测字段级越权与嵌套遍历，含"内省关闭"时的替代探测手段
whenToUse: 指纹或 JS 里出现 graphql/gql/apollo，或需要枚举接口清单却找不到 REST 文档时
role: exploit
category: 验证
tags: [graphql, introspection, schema, batching, 接口枚举]
enabled: true
---

# GraphQL 攻击面

> GraphQL 的漏洞不在"注入"，而在**授权粒度**：单个查询可能同时暴露多个对象，而鉴权只校验了最外层。

## 一、定位端点

用 `runs/tools/paths_graphql.txt`（21 条）探测。判据：返回 JSON 含 `data`/`errors` 且 `errors` 提到 GraphQL。

**快速确认**：
```bash
curl -s -X POST "https://target/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
# 返回 {"data":{"__typename":"Query"}} → 确认是 GraphQL
```

## 二、内省拿 schema（首选）

```bash
curl -s -X POST "https://target/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name kind fields{name args{name type{name kind ofType{name}}}}}}}"}'
```

**判据**：返回 types 列表 → 拿到**全部接口与字段清单**。

### 内省被关闭时（常见防御）

| 替代方法 | 说明 |
|---|---|
| 字段建议 | 发错误查询，看 `Did you mean "xxx"` 类型建议 |
| 猜测常见字段 | `user`/`users`/`me`/`viewer`/`node(id:$id)` |
| 前端源码 | GraphQL 客户端的 query 常量常在前端 JS 里 |
| `__type(name:"User")` | 内省被部分关闭时，单类型查询可能仍可用 |

## 三、四类测试点

### 1. 未授权字段访问

```graphql
{ users { id name phone } }
```
**判据**：无凭据返回用户列表（含 PII）。

### 2. 字段级越权（最隐蔽）

```graphql
{ me { id name email role } }
```
带上普通用户凭据，看能否读到 `role`/`isAdmin`/`password` 等本不该返回的字段。

### 3. 批量查询（一次拿大量）

```graphql
{ u1: user(id:1){name} u2: user(id:2){name} u3: user(id:3){name} }
```
GraphQL 支持别名 **一次请求查多个对象**——同样 5 个 id，只算 **1 次请求**。

**也可用数组批量**（若启用）：
```json
[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"}]
```

### 4. 嵌套遍历（放大危害）

```graphql
{ user(id:1){ orders { items { product { name price } } } } }
```
一层鉴权缺失可能导出整棵关联对象树。

## 四、判定标准

| 结果 | 结论 |
|---|---|
| 无凭据执行 `users` 返回 PII | ✅ 未授权（高） |
| 普通用户查询到 `role`/`isAdmin` | ✅ 字段级越权 |
| 用别名一次查多个他人对象 | ✅ 批量越权 |
| 内省开放但所有查询都需鉴权 | ⚠️ 低（信息泄露级） |
| 只有 `__typename` 可用 | ❌ 无价值 |

## 五、证据要求

1. 内省响应片段（证明 schema 可读，或说明已关闭）
2. 未授权/越权查询的请求与响应（含字段值，脱敏）
3. 说明"一次请求查了多少对象"

## 六、失败判据

- 所有查询返回 `Unauthorized` → 鉴权正常
- 内省关闭且无法猜出字段 → 成本高，转 REST
- 只返回 `null` 无数据 → 可能无权限

## 七、边界

- **只取 1–3 条样本**，不做批量翻页/全量遍历
- 别名批量测试**只做 3–5 个**，不构造大 payload
- 禁止用 GraphQL 做 DoS（深嵌套、循环引用）

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 以为内省关闭就没法测 | 前端 JS 里常有完整 query 常量 |
| 忽略 GraphQL 一般在 POST | 用 GET 测会 405 |
| 忘记 `Content-Type: application/json` | 大部分服务端要求 |
| 把 `errors` 里的 introspection 提示当漏洞 | 只是信息泄露级 |
