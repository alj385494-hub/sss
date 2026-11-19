---
name: tech-deserialization
description: 【验证】反序列化识别与判定：从特征指纹（base64 序列化串、Java 魔法头、PHP O:、.NET ViewState）判断是否可反序列化，用延时/回显/OOB 三法确认，不做 getshell 级利用
whenToUse: 参数呈序列化特征、使用 Java/.NET/PHP 且组件版本可疑、或遇到 ViewState/Session 类二进制参数时
role: exploit
category: 验证
tags: [deserialization, java, php, dotnet, viewstate, ysoserial, 反序列化]
enabled: true
---

# 反序列化识别与判定

> 判定目标只有两个：**"服务端会不会反序列化我的输入"** 以及 **"能不能证明影响"**。
> **不做 getshell**——那是越界。

## 一、识别特征（先判断有没有）

| 语言 | 特征 |
|---|---|
| **Java** | base64 解码后以 `AC ED 00 05`（`rO0AB`）开头；或 `H4sI`（gzip 后） |
| **PHP** | `O:8:"stdClass":...`、`a:2:{...}`、`s:5:"hello";` |
| **.NET** | `__VIEWSTATE` 参数、`AAEAAAD/////` 开头（BinaryFormatter） |
| **Python** | `\x80\x04`（pickle）、`cos\nsystem`（旧协议） |
| **Ruby** | `\x04\x08` 开头 |

**去哪找**：Cookie、隐藏表单字段、`data=`/`param=` 参数、Java 的 `JSESSIONID` 之外的自定义会话参数。

## 二、三法确认（按安全程度排序）

### 1. 延时法（最安全，首选）
```
注入会造成延时的 gadget 链（如 DNS 解析/线程 sleep）
判据：响应延迟 ≥2.5s 且可重复
```
**注意**：不要用会造成破坏的链。

### 2. OOB 法（最可靠）
```
注入触发 DNS/HTTP 请求的链，指向你的一次性 OOB 域名
判据：OOB 平台收到回连
```

### 3. 回显法
```
注入读取环境变量的链（如 Java 的 Runtime.exec("env")）
判据：响应里出现环境变量片段
```
**只读到环境变量即停**，不执行其他命令。

## 三、常见入口

| 入口 | 说明 |
|---|---|
| 自定义 Cookie | 反序列化后当会话用 |
| `__VIEWSTATE` | .NET 站点，看是否启用 MAC 校验 |
| RMI/JMX/HTTP Invoker | Java 服务端口 |
| Fastjson/Jackson `@type` | JSON 反序列化（改 `@type` 看报错） |
| Shiro `rememberMe` | Cookie 值 base64 → AES 解密后是序列化数据 |

## 四、判定标准

| 结果 | 结论 |
|---|---|
| 延时/OOB 证明服务端反序列化 | ✅ 高（需说明可执行） |
| 只能触发报错，无延时/回连 | ❌ 不算 |
| 有序列化参数但服务端用了白名单 | ❌ 不算 |
| Shiro 默认密钥可解密（仅解密成功） | ⚠️ 中（还要能构造利用） |

## 五、证据要求

1. 原始参数值（截断展示）+ 解码后的序列化特征
2. 延时测量的两次对比，或 OOB 回连记录
3. 说明影响的**最小证明**（如读到环境变量片段）

## 六、失败判据

- 参数看起来像 base64 但解码后不是序列化格式 → 不是这条路
- 延时波动大无法重复 → 放弃
- 目标有严格白名单且无绕过 → 放弃
- 需要特定依赖版本但版本不对 → 放弃

## 七、边界（**最重要**）

| 禁止 | 原因 |
|---|---|
| 用 ysoserial 打 getshell 链 | 越界；平台也不接受"能 RCE 但没证据" |
| 反弹 shell / 写文件 / 留后门 | 严重越界 |
| 用破坏性 gadget（删文件/关机） | 影响业务 |
| 对生产系统反复触发 | 可能造成拒绝服务 |

**只允许**：延时证明 + OOB 证明 + 读环境变量片段。

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 把 base64 当反序列化 | 先解码看头部 |
| 忽略 gzip 压缩 | `H4sI` 开头要先解压再看 |
| 用 JSESSIONID 测 | 那是容器会话 ID，不是序列化数据 |
| 忘记看依赖版本 | gadget 链强依赖版本 |
