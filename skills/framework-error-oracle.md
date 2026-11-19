---
name: framework-error-oracle
description: 【侦察】框架指纹与错误信息利用：从报错 JSON/堆栈/表单令牌识别框架与路由约定，把"模块不存在/控制器不存在/方法不存在"这类差异做成枚举 oracle，并判断哪些泄露值得继续投入
whenToUse: 目标返回自定义 JSON 错误、堆栈页、框架特征字段（如 __token__、X-Powered-By），或需要摸清内部路由与命名空间时
role: recon
category: 侦察
tags: [framework, fingerprint, error, oracle, routing, 错误信息, 指纹]
enabled: true
---

# 框架指纹与错误信息利用

> 报错是最便宜的侦察。**能区分"哪一层不存在"的错误信息，等于免费的路由地图。**

## 一、什么时候用

- 任意路径返回统一的 JSON 错误（`{"code":0,"message":"..."}`）
- 500 页面带堆栈/文件路径/行号
- 表单里有框架特征字段
- 想确认目标用的是什么框架（决定后续打法）

## 二、框架指纹速查

| 特征 | 框架/产品 |
|---|---|
| 表单隐藏域 `__token__`、`__hash__` | **ThinkPHP** |
| 路由 `/{module}/{controller}/{action}` + `module not exist` | ThinkPHP/自研 PHP 框架 |
| 错误含 `app\xxx\controller\Xxx` | PHP（PSR-4 / ThinkPHP 6） |
| `/actuator`、`Whitelabel Error Page` | Spring Boot |
| `X-Powered-By: Express`、`Cannot GET /x` | Express/Node |
| `Server: none` + 自定义 JSON 统一错误 | 自研网关（常见于国内教务/一卡通） |
| `Welcome to IdP Server` | **Shibboleth IdP 默认页** |
| `Apereo CAS` 样式欢迎页 | CAS 单点登录 |
| `.do`、`.action` 后缀 | Struts2 / 老 Java |

## 三、把错误信息变成 oracle

### 三级路由 oracle（PHP 常见）

| 请求 | 返回 | 结论 |
|---|---|---|
| `/foo/` | `module not exists:foo` | 模块不存在 |
| `/auth/` | 不是 module 错误 | **模块存在** |
| `/auth/oauth/` | `controller not exists:...` | 模块存在、控制器不存在 |
| `/auth/oauth/x` | `method not exists:app\auth\controller\Oauth->x` | 控制器存在，**方法名猜错**，且泄露完整命名空间 |

**用法**：先用少量常见模块名（`index`/`api`/`auth`/`admin`/`home`/`system`/`user`）定位存在的模块，
**不要用大字典扫**——单目标 ≤10 个模块，命中就停。

### 为什么有价值

1. 拿到**内部命名空间**（`app\auth\controller\Oauth`）→ 可推断项目结构与其他模块名
2. 确认**哪些模块存在** → 后续只对存在的模块找入口
3. 若错误里带**文件绝对路径**，可判断部署路径与是否 debug 模式

## 四、判定标准（哪些值得继续）

| 泄露内容 | 价值判断 |
|---|---|
| 内部命名空间 + 路由约定 | ✅ 高：直接指引后续测试 |
| 框架/版本号（可匹配 Nday） | ✅ 中高：需配合已知漏洞 |
| 绝对路径（`/www/wwwroot/xxx`） | ⚠️ 低：多为配置错误级 |
| 内网地址（`192.168.x`、`10.x`） | ⚠️ 低：**多数平台列为忽略项**，但其中的**参数**（orgId/schoolCode）有后续价值 |
| Shibboleth/CAS 默认页 | ❌ 无价值 |
| 只有"系统繁忙"这类泛化错误 | ❌ 无价值（说明错误处理规范） |

**关键原则**：错误信息**本身**很少能单独提交，它的价值是**指引下一步**。

## 五、证据要求

1. 触发错误的完整请求（含路径）
2. 错误响应原文（保留框架/命名空间字段）
3. **oracle 对照**：至少两个请求的对比（一个"不存在"、一个"存在"）
4. 结论：从这条泄露推出的下一步动作

## 六、失败判据

- 所有路径返回同一段泛化错误 → 错误处理已规范化，放弃
- 错误页只有状态码无内容 → 无价值
- 模块枚举 10 个全是"不存在" → 该路由约定不成立，换思路

## 七、边界

- **不做字典爆破**：模块/控制器枚举 ≤10 个/目标，间隔 ≥1s
- 不主动制造异常触发报错（如故意传畸形参数导致写日志）——会污染目标日志
- 错误信息里若含凭据/密钥：只记录存在性，打码后可写进报告
- 内网地址泄露：按平台口径通常不单独提交，只作为线索

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 把 SPA 回落页当错误页 | 795B/固定长度 + HTML 内容 = 前端路由兜底，不是后端错误 |
| 用大字典枚举模块 | 触发风控、产生噪音，还可能打挂小站 |
| 只看到"404"就放弃 | 很多自研框架返回 404 但 body 里有关键错误信息 |
| 忽略大小写差异 | `Module not exist` vs `module not exist` 可能来自不同层 |
