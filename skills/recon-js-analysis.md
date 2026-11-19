---
name: recon-js-analysis
description: 【侦察】前端 JS 系统化分析：从 bundle 拆分、sourcemap 还原、webpack 模块图、到接口/密钥/内网地址提取，产出一份可用的"前端情报清单"
whenToUse: 目标是 SPA/小程序/后台系统，需要从大量 JS 里系统性地挖接口、密钥、内网地址时；或零散 grep 效率太低时
role: recon
category: 侦察
tags: [javascript, bundle, sourcemap, webpack, recon, 前端分析]
enabled: true
---

# 前端 JS 系统化分析

> 不要一上来就 grep 关键词。先**搞清有哪些 JS**，再按优先级读。

## 一、清点资源（先列全）

```bash
# 1. 首页引用的所有 JS
curl -s "$URL" -A "$UA" | grep -oE '(src|href)="[^"]+\.(js|css)[^"]*"' | sed 's/.*="//;s/"//' | sort -u

# 2. 动态加载的 chunk（webpack 运行时里有 chunk 映射表）
grep -oE '[0-9]+\.[a-f0-9]{6,}\.js|[a-z_]+\.async\.js' index.js | sort -u

# 3. 全量下载到本地
mkdir -p js && while read u; do curl -s "$u" -o "js/$(basename "$u")"; done < list.txt
```

**分类**：
| 类型 | 文件名特征 | 价值 |
|---|---|---|
| 框架包 | `chunk-vendors`、`vendor`、`framework` | ❌ 低（几乎无业务信息） |
| 业务主包 | `index`、`app`、`main` | ✅ 高 |
| 页面 chunk | `p__xxx`、`xxx.async` | ✅ 最高（含具体接口） |
| 工具库 | `crypto-js`、`lodash`、`axios` | ⚠️ 中（看配置） |

## 二、四类提取（按价值）

### 1. 接口路径（最高优先级）

```bash
# 引号内以 / 开头的路径
grep -ohE '"\/[a-zA-Z][a-zA-Z0-9_/-]{3,45}"' js/*.js | tr -d '"' | sort -u

# 拼接形式（base + path）
grep -ohE '(url|api|baseURL)\s*[:=]\s*["'"'"'][^"'"'"']{2,60}' js/*.js | sort -u
```

**注意**：可能只有相对路径（`/auth/getToken`），base 在另一个变量里 → 要找 base 定义，或观察是否存在遗留的内网/测试 URL（常带完整 base）。

### 2. 密钥与凭据

```bash
grep -ohiE "(appsecret|aeskey|aes_key|secret|password|privatekey|accesskey)\s*[:=]\s*['\"][^'\"]{6,60}" js/*.js
grep -ohE "CryptoJS\.(AES|DES|enc)\.(encrypt|decrypt)\([^)]{0,120}" js/*.js
```

### 3. 内网地址与调试残留

```bash
grep -ohE 'https?://([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?[^"'"'"' ]*' js/*.js | sort -u
grep -ohE 'https?://[a-z0-9.-]*(internal|local|test|dev|uat)[a-z0-9.-]*' js/*.js | sort -u
```

> 内网地址本身多为忽略项，但**其中的参数**（orgId、schoolCode、tenantId）往往能直接用于其他接口。

### 4. 隐藏页面/路由

```bash
grep -ohE 'path\s*:\s*["'"'"'][^"'"'"']{2,40}' js/*.js | sort -u      # vue-router
grep -ohE 'component\s*:\s*\(\)\s*=>\s*import' js/*.js               # 懒加载
```

## 三、sourcemap（有就用，别放过）

```bash
# 逐个试
for u in $(cat list.txt); do
  curl -s -o /dev/null -w "%{http_code} $u.map\n" "${u}.map"
done
```

命中后：`.map` 里有 `sources`（原始文件路径）与 `sourcesContent`（原始源码）→ **等于拿到源码**。

**用途**：找注释掉的接口、真实变量名、后端域名、开发备注。

## 四、产出格式（写成清单文件）

```markdown
## 前端情报清单
### 接口（N 个）
- /auth/getToken  (无参数)      ← 无需登录?
- /alumuns/getAlumnusConfig
### 密钥
- AES key=xxxx（登录口令加密）
### 内网/调试
- http://192.168.x.x:8166/server/... → 反推前缀 /server/
### 隐藏路由
- /admin/audit
```

**这份清单就是后续所有接口测试的输入。**

## 五、判定标准

| 产出 | 价值 |
|---|---|
| 拿到完整接口清单 | ✅ 高（后续测试的入口） |
| 拿到硬编码密钥 | ✅ 中（要看用途） |
| 拿到 sourcemap 源码 | ✅ 中高（可做代码审计） |
| 只有框架包内容 | ❌ 无价值 |

## 六、失败判据

- 所有 JS 都是压缩后的框架代码，无业务路径 → 接口在服务端渲染，转 HTML 分析
- 有 sourcemap 但内容空 → 放弃
- JS 总量 <10KB → 站点太简单，转其他线索

## 七、边界

- 只分析**公开可下载**的前端资源
- 不破解混淆加密的授权校验逻辑
- 提取到的密钥在报告里打码

## 八、常见坑

| 坑 | 说明 |
|---|---|
| 只 grep 首页 JS | 业务代码常在动态 chunk 里 |
| 忽略 `catch`/`finally` 里的 URL | 异常路径也常写死接口 |
| 把 `chunk-vendors` 当宝 | 里面全框架代码，浪费时间 |
| 忘记试 `.map` | 有 sourcemap 等于直接拿源码 |
