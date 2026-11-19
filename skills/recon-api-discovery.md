---
name: recon-api-discovery
description: 【侦察】API 面发现：从 Swagger/OpenAPI 文档、移动端包、第三方 SDK、错误页、历史版本、CORS 预检六个来源找接口清单，产出可测试的 API 面
whenToUse: 目标是 API 驱动（SPA/小程序/APP），需要一份完整接口清单作为后续测试输入时
role: recon
category: 侦察
tags: [api, discovery, swagger, openapi, mobile, sdk, 接口发现]
enabled: true
---

# API 面发现

> 目标是**拿到一份尽可能完整的接口清单**。清单越全，后面测未授权/越权的命中率越高。

## 一、六个来源（按命中率排序）

### 1. 文档端点（最快）

```bash
for p in swagger-ui.html swagger-resources v2/api-docs v3/api-docs openapi.json \
         api-docs swagger.json doc.html graphql graphiql; do
  printf "%-20s %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "$U/$p")"
done
```

**注意**：
- 有些是 `/doc.html`（knife4j）、`/swagger-ui/index.html`
- 有些放在二级路径：`/api/swagger-ui.html`、`/{module}/v2/api-docs`
- 大量返回 404 但 body 是**自定义 JSON 错误** → 说明有网关，接口可能在其他前缀

### 2. 前端 JS（覆盖最广）

见 `recon-js-analysis`。核心是提取路径 + 找 base。

### 3. 移动端包（接口最原始）

| 目标 | 手段 |
|---|---|
| Android APK | 解包后搜 `http`、`/api/`、`baseUrl` |
| 小程序 | 反编译 `.wxapkg`，搜同样关键词 |
| iOS IPA | 解包 `Payload/*.app` 二进制搜字符串 |

**为什么优先**：移动端常保留**老版本/内部接口**，而 Web 端已下线。

### 4. 第三方 SDK / 开放平台

| 来源 | 说明 |
|---|---|
| 开放平台文档 | `open.<域>` 常有完整 API 列表与鉴权说明 |
| SDK 源码（npm/maven） | SDK 里写死所有接口路径与参数 |
| 合作伙伴文档 | 有时比官方更全 |

### 5. 错误页与路由 fallback

- 传错参数看报错里的接口名
- 访问不存在的路由，看是否有"可用接口"提示
- 405（方法不允许）说明**路径存在**

### 6. CORS 预检与 OPTIONS

```bash
curl -s -X OPTIONS "$U/api/user" -i | head -20
```
`Allow` 头会列出该路径支持的方法 → 间接确认路径存在。

## 二、补齐接口细节

拿到路径后，还需要知道**参数**：

| 手段 | 做法 |
|---|---|
| Swagger 定义 | 直接给参数名/类型/必填 |
| JS 里的调用点 | 搜该路径，看传入对象 |
| 报错信息 | 缺参数时返回"xxx不能为空" |
| 试错 | 传空对象，看报错逐个补 |

## 三、产出格式

```markdown
## API 面清单
| 路径 | 方法 | 鉴权 | 参数 | 来源 | 状态 |
|---|---|---|---|---|---|
| /server/auth/getToken | POST | 需code签名 | schoolCode | JS | 待测 |
| /api/order/list | GET | Bearer | page,limit | Swagger | 待测 |
```

**"鉴权"列要填**：无凭据 / 需登录 / 需签名 / 未知 —— 这决定后面用哪条链。

## 四、判定标准

| 结果 | 说明 |
|---|---|
| 拿到 ≥20 个路径且有参数 | ✅ 完成 |
| 只拿到文档但无鉴权信息 | ⚠️ 需补 |
| 全部 404 且无自定义错误 | ⚠️ 可能是纯静态站 |

## 五、失败判据

- 所有文档端点 404 + JS 无路径 + 无移动端 → 该站无 API 面，转页面级测试
- 接口全在一个签名网关后且无法复算 → 记录后转其他资产

## 六、边界

- 只读公开资源；不反编译付费/授权应用
- 移动端包只从**官方渠道**下载
- 接口清单是内部资产，不外传

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 只试根路径的 swagger | 常在二级路径或需登录 |
| 忽略 405 | 405 说明路径存在，很有价值 |
| 把 SPA 回落页当接口 | 判长度与首页是否一致 |
| 忘记看移动端 | Web 关了的老接口常还活着 |
