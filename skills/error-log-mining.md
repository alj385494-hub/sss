---
name: error-log-mining
description: 【侦察】错误日志与调试信息挖掘：发现可访问的 error.log/debug/actuator 日志，从中提取内网地址、内部接口、SQL、凭据与版本，并区分"有情报价值"与"无意义泄露"
whenToUse: 目标暴露了日志文件、debug 页面、actuator/telescope 等调试端点，或报错页泄露堆栈与路径时
role: recon
category: 侦察
tags: [log, error, debug, actuator, info-leak, 日志, 信息泄露]
enabled: true
---

# 错误日志与调试信息挖掘

> 日志本身不是漏洞，**日志里的情报**才是。判断标准是：看完日志，你是否拿到了新的攻击路径或凭据线索。

## 一、什么时候用

- 站点返回 500 时**页面带堆栈**（说明 `debug=true`）
- 存在通用日志路径：`/error.log`、`/debug.log`、`/logs/`、`/log.txt`
- Java 应用：`/actuator`、`/actuator/logfile`、`/actuator/env`、`/actuator/heapdump`
- ThinkPHP/Laravel：`/runtime/log/`、`/storage/logs/`
- 有目录列表（`autoindex on`）里能看到 log

## 二、探测路径清单（只读）

```
/error.log                    /logs/error.log
/debug.log                    /logs/debug.log
/log/                         /logs/
/app.log                      /application.log
/runtime/log/                 /storage/logs/
/actuator                     /actuator/logfile
/actuator/env                 /actuator/health
/telescope                    /_ignition/health-check
/phpinfo.php                  /server-status
```

判据：返回 200 且内容是**日志格式**（时间戳 + 级别 + 消息），不是 SPA 回落页

## 三、从日志里提取什么（按价值排序）

| 情报 | 用途 |
|---|---|
| **内网地址**（`10.x`、`192.168.x`、内部域名） | 新攻击面、SSRF 目标、内网拓扑 |
| **内部接口路径**（`/internal/xxx`、`/api/v2/...`） | 未测试的接口 |
| **数据库连接串 / 用户名** | 凭据线索（不实连） |
| **SQL 语句 + 表名** | 数据库结构、注入点线索 |
| **框架/组件版本与报错栈** | 精准 Nday 匹配 |
| **第三方服务 key / 回调地址** | 供应链与 SSRF |
| **员工邮箱/用户名格式** | 后续账号枚举（注意平台口径） |

## 四、执行步骤

### 步骤 1 · 发现日志
逐个请求上面清单（单站 ≤10 个路径，间隔 ≥1s）。
**用浏览器 UA**（部分站点对默认 UA 返回 404）。

### 步骤 2 · 有界下载
```bash
# 先看大小，别直接下 100MB
curl -sI <url> | grep -i content-length
# 只取头部 200KB（日志开头常有版本与环境信息）
curl -s -r 0-204800 <url> -o /tmp/log_head.txt
```
判据：拿到内容且是文本日志

### 步骤 3 · 情报提取
```bash
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /tmp/log_head.txt | sort -u
grep -oE "(jdbc:[a-z]+://[^ ]+|mongodb://[^ ]+|redis://[^ ]+)" /tmp/log_head.txt | head -5
grep -oiE "(/[a-z0-9_]+)+(api|internal|admin)[a-z0-9_/]*" /tmp/log_head.txt | sort -u | head -20
```

### 步骤 4 · 交叉验证
把提取到的内部接口/地址拿去验证是否可达（`curl -I`，只读）。
判据：能访问 → 变成新的测试目标；不能访问 → 只作为线索记录

## 五、判定标准

| 情形 | 结论 |
|---|---|
| 日志含内网地址 + 可访问的内部接口 | ✅ 中高价值（新攻击面） |
| 日志含数据库连接串/口令 | ✅ 高价值（但不实连） |
| 日志只含普通的 404 记录 | ❌ 无意义泄露 |
| `actuator/env` 返回配置（含脱敏） | ⚠️ 视脱敏程度定；未脱敏的口令才算 |
| 只有 `phpinfo` / 版本号 | ⚠️ 低价值（多数平台视为配置错误级） |

## 六、证据要求

1. 日志 URL + 状态码 + 大小
2. 截图/文本片段（**内网 IP 可在报告内保留，但凭据必须打码**）
3. 提取到的情报清单 + 验证结果（可达性）

## 七、失败判据

- 全部日志路径 404/403 → 放弃
- 日志内容全是访问记录，无内部信息 → 无价值
- `actuator` 全端点 401 → 鉴权正常

## 八、边界

- **只读**：不删除、不覆盖、不触发写日志的异常（避免污染）
- 单文件下载上限 1MB；发现大文件只取头部
- 日志里的人名/手机号等个人信息：**只统计条数，不摘录**
- 不把日志内容原样贴进报告超过必要长度

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 默认 UA 被拦 | 用浏览器 UA 再试一遍（同目录发现的双 UA 规则） |
| 把 SPA 回落页当日志 | 长度与首页一致 + 内容是 HTML → 不是日志 |
| 下载整个日志 | 可能几百 MB，还会触发告警 |
| 看到连接串就去连 | 越界；只记录不连接 |
