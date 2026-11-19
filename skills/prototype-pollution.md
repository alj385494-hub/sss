---
name: prototype-pollution
description: 【验证】原型链污染：识别 JS 合并/克隆类参数（__proto__/constructor.prototype），判定是否污染到全局对象，以及从"能污染"升级到"能影响鉴权/命令执行"的判定路径
whenToUse: 后端是 Node.js/前端有深度合并逻辑，且参数可传嵌套 JSON（如 config/settings/options）时
role: exploit
category: 验证
tags: [prototype-pollution, javascript, nodejs, merge, 原型链]
enabled: true
---

# 原型链污染

> 判定分两步：**能不能污染**（技术层）与**污染后有什么影响**（价值层）。
> 只证明第一步通常不够。

## 一、识别可疑点

| 特征 | 说明 |
|---|---|
| 接口接收**嵌套 JSON**（`{"a":{"b":1}}`） | 深度合并的原料 |
| 参数名是 `config`/`settings`/`options`/`data`/`params` | 常直接 merge |
| 前端用 `lodash.merge`/`Object.assign`/`$.extend(true,...)` | 已知易污染 |
| 后端 Node.js（Express/Koa） | 原型链污染的主场 |
| 出现 `__proto__` 被拒绝的报错 | 说明有过滤但可能在别处漏 |

## 二、探测 payload

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
{"a": {"__proto__": {"polluted": "yes"}}}
```

**变体**（绕过简单过滤）：
```json
{"__pro__proto__to__": {"polluted":"yes"}}
{"constructor[prototype][polluted]": "yes"}
```

## 三、判定"是否真的污染"（关键）

污染的是**服务端全局 Object.prototype**，验证方法：

| 方法 | 做法 |
|---|---|
| **行为差异** | 污染一个被业务逻辑读取的属性（如 `isAdmin`、`role`），看权限是否变化 |
| **报错泄露** | 污染后触发报错，看错误里是否含被污染的值 |
| **OOB** | 污染某个会被拼进 URL/命令的属性，观察回调 |
| **间接探测** | 先污染 `toString`/`valueOf` 相关属性，看响应异常 |

**最常见的验证**：污染 `{"__proto__":{"isAdmin":true}}` 后，用普通账号访问管理接口。

## 四、升级路径（决定价值）

| 升级方向 | 条件 |
|---|---|
| **鉴权绕过** | 应用用 `req.user.isAdmin` 之类的原型属性判断权限 |
| **RCE** | 存在 `child_process` 且参数从被污染属性取（如 `shell`、`env`、`NODE_OPTIONS`） |
| **SSRF** | 污染的属性被用于拼接请求地址 |
| **仅 DoS** | 污染导致服务异常 → 属拒绝服务，**价值低且不测** |

## 五、判定标准

| 结果 | 结论 |
|---|---|
| 污染 + 权限变化（普通用户变管理员） | ✅ 高 |
| 污染 + 可影响下游（SSRF/RCE 链） | ✅ 高 |
| 污染成功但无任何影响 | ⚠️ 低（多数平台不认） |
| 只有 `__proto__` 字面量被回显 | ❌ 不算 |

## 六、证据要求

1. 污染请求（含 payload）
2. **影响证明**：对比污染前后的权限/响应差异
3. 说明污染点在源码中的位置（若拿到 sourcemap）

## 七、失败判据

- `__proto__` 被严格过滤且无可绕变体 → 放弃
- 污染后无任何行为差异 → 记录但不提交
- 目标不是 Node.js/JS 运行时 → 无此类面

## 八、边界

- **不做 DoS 型污染**（会把服务打挂）
- 不污染会导致数据损坏的属性
- 验证只读：污染后只读验证，不做写操作

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 以为"参数被接受"就是污染 | 要看服务端全局对象是否真的变了 |
| 忽略 JSON 深度限制 | 有的框架限制嵌套层数 |
| 只在客户端测 | 真正的危害在服务端 |
| 用 DoS payload | 价值低且影响业务 |
