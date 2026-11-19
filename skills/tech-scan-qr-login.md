---
name: tech-scan-qr-login
description: 【验证】扫码登录与第三方 OAuth 回调（钉钉/企业微信/飞书/微信）：从回调地址与 client_id 出发，测 redirect_uri、state、code 复用，重点查 appSecret/Bearer Token 是否在前端泄漏（泄漏即可直接调官方 API 换 token）
whenToUse: 目标登录页是"钉钉扫码/企业微信扫码/飞书登录"，或前端出现 client_id / appId / corpId / redirect_uri 时
role: exploit
category: 验证
tags: [oauth, dingtalk, wecom, qr-login, appsecret, bearer, 扫码登录]
enabled: true
---

# 扫码登录与第三方 OAuth 回调

> 国内系统（尤其教育/政企）大量用钉钉/企微/飞书扫码登录。
> **最高价值不是绕 state，而是"appSecret 或 Bearer Token 在前端泄漏"——泄漏后可直接调官方 API 换 token，等于拿到任意用户身份。**

## 一、先摸清三要素

从前端（登录页 HTML / JS / 回调页）找：

| 要素 | 长相 |
|---|---|
| **client_id / appKey / appId** | `ding` 开头（钉钉）、`ww` 开头（企微）、`cli_` 开头（飞书） |
| **回调地址** | `redirect_uri=`、`/user/home/auth.html`、`/oauth/callback` |
| **state / code 处理位置** | 前端是否参与校验 |

```bash
# 一条命令定位
curl -s "$URL" | grep -oE "(client_id|appid|appKey|corpId|redirect_uri|state)=[^&\"' ]+"
```

## 二、五个测试点（按价值）

### 1. ★ appSecret / Bearer Token 是否在前端泄漏（最高价值）

**参考案例**（奇安信攻防社区 `/share/1471`「OAuth2.0漏洞分析」，2026-11-13 抓取）：

- **0x04 Bearer Token 生成接口未授权访问**：小程序解包后搜索 `Bearer`，发现 `loadToken()` 会生成 Bearer Token → 该接口无鉴权 → 直接用它调业务接口
- **0x06 ID、Secret 泄漏**：在前端/小程序里发现**钉钉的 appId 与 appSecret** → **直接用官方 API 换 access_token**（`https://open-dev.dingtalk.com/apiExplorer` 里有现成接口）

**怎么做**：
```bash
# 1. 全量 JS / 小程序包里搜
grep -rhoiE "(appsecret|app_secret|secret|access_?token|bearer)\s*[:=]\s*['\"][^'\"]{8,}" js/
# 2. 命中 appSecret → 用官方接口换 token（只做身份确认，不调业务写接口）
#    钉钉：POST https://oapi.dingtalk.com/gettoken?appkey=<AK>&appsecret=<SK>
# 3. 命中 Bearer → 直接带上去请求一个需要登录的只读接口
```

**判据**：换到 token 并能调通一个需要身份的**只读**接口（或 `gettoken` 返回 `errcode:0`）。

### 2. redirect_uri 校验缺陷

| 变体 | 例子 |
|---|---|
| 加子域 | `redirect_uri=https://<目标>.evil.com/cb` |
| 加路径 | `redirect_uri=https://<目标>/evil` |
| 参数污染 | 传两个 `redirect_uri` |
| 编码绕过 | `https://<目标>%2f@evil.com` |

**判据**：`code` 被发到攻击者可控地址（OOB 或自建回调页收到）。

### 3. state 缺失或不校验

删掉 `state` 或改成任意值，看流程是否仍能完成。
**判据**：能完成 → 存在 CSRF 风险（**价值中低，多数平台判低**）。

### 4. code 复用

同一 `code` 用两次换 token。
**判据**：第二次仍返回 token（OAuth2 要求一次性）。

### 5. postMessage XSS / 回调页注入

参考案例 0x07：`postMessage` 无 origin 校验，或回调页把 `code`/`error` 直接写进 DOM。
**判据**：能跨域注入脚本（需浏览器验证）。

## 三、钉钉 / 企微 / 飞书 的差异点

| 平台 | 特征 | 重点 |
|---|---|---|
| **钉钉** | `client_id=ding...`、`login.dingtalk.com` | appKey/appSecret 泄漏 → `gettoken` 直换；扫码免登 `sns/getuserinfo_bycode` |
| **企业微信** | `ww...`、`open.work.weixin.qq.com` | `corpid/corpsecret` 泄漏 → `gettoken`；`code` 换 `userid` |
| **飞书** | `cli_...`、`open.feishu.cn` | `app_id/app_secret` 泄漏 → `tenant_access_token` |
| **微信开放平台** | `appid=wx...` | 需 AppSecret；`code` 换 `access_token`+`openid` |

**共同点**：一旦拿到 `secret`，**服务端身份体系对你就不设防了**。

## 四、判定标准

| 结果 | 结论 |
|---|---|
| appSecret 泄漏 + 换 token 成功 | ✅ 高（可冒充任意用户/拿企业数据） |
| Bearer Token 生成接口未授权 | ✅ 高 |
| redirect_uri 可跳攻击者域 + 抓到 code | ✅ 高 |
| code 可复用 | ✅ 中 |
| state 不校验 | ⚠️ 低（多数平台忽略） |
| 只有 client_id（公开值） | ❌ 不算 |

## 五、证据要求

1. 泄漏点（文件路径 + 片段，**secret 打码**，只留前后各 4 位）
2. 换 token 的请求与响应（`errcode:0` / `access_token` 存在）
3. 用该 token 调通一个**只读**接口的响应
4. 说明影响：能冒充谁、能读什么

## 六、失败判据

- 只有 `client_id`（本来就是公开的）→ 不算
- `redirect_uri` 精确白名单且无绕过 → 放弃
- 扫码流程全在官方域名完成、目标只做跳转 → 无面
- 拿不到账号（扫码需真实企业成员）→ 记录后放弃

## 七、边界（红线）

| 禁止 | 原因 |
|---|---|
| 用泄漏的 secret 调**业务写接口**（发消息/改通讯录） | 越界，会影响真实员工 |
| 冒充真实员工登录 | 越界 |
| 冒用他人 code/token | 越界 |
| 把 secret 明文写进报告或外传 | 泄密 |

**只允许**：换 token 证明有效 + 读 1 个只读接口证明身份可冒充。

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 把 client_id 当密钥 | client_id 是公开的，前端必然可见 |
| 只看登录页不看小程序包 | secret 常在小程序/APP 里 |
| 忽略"Bearer"关键词 | 参考案例就是靠搜 `Bearer` 找到的 |
| 换到 token 就去列举通讯录 | 越界；只验证身份即可 |
