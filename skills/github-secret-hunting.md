---
name: github-secret-hunting
description: 【侦察】GitHub/代码托管平台泄露挖掘：用代码搜索语法定位目标组织的配置文件、密钥、数据库连接串与内部地址，含搜索关键词表、历史提交挖掘与验证边界
whenToUse: 目标有公开的 GitHub/Gitee/GitLab 组织或仓库，或 JS 里出现内部服务名/仓库名，需要找凭据、内部地址、源码线索时
role: recon
category: 侦察
tags: [github, secret, leak, code-search, credential, 代码泄露, 信息收集]
enabled: true
---

# 代码托管平台泄露挖掘

> 公开仓库里的 `.env`、配置文件、CI 日志、历史提交，经常比站点本身更容易拿到内部信息。

## 一、什么时候用

- 目标有公开组织账号（`github.com/<org>`）
- JS/接口报错里出现内部仓库名、服务名
- 目标是软件公司 / 高校信息中心（爱在 GitHub 放系统源码）
- 需要数据库连接串、第三方 API Key、内网地址

## 二、搜索语法（GitHub 代码搜索）

| 语法 | 用途 | 例子 |
|---|---|---|
| `org:<组织>` | 限定组织 | `org:example password` |
| `filename:` | 按文件名 | `filename:.env`、`filename:config.php` |
| `path:` | 按目录 | `path:config/ password` |
| `language:` | 按语言 | `language:php mysql` |
| `extension:` | 按扩展名 | `extension:sql`、`extension:bak` |
| `in:file` / `in:path` | 限定匹配位置 | `in:file "jdbc:mysql"` |
| `"精确串"` | 精确匹配 | `"api_key = "` |

**常用组合**：
```
org:<org> filename:.env
org:<org> "jdbc:mysql" OR "mongodb://"
org:<org> filename:*.yml "password"
org:<org> "BEGIN RSA PRIVATE KEY"
org:<org> "accessKeyId"
```

## 三、关键词表（按优先级）

| 类别 | 关键词 |
|---|---|
| **数据库** | `jdbc:mysql`、`jdbc:sqlserver`、`mongodb://`、`redis://`、`postgresql://`、`DB_PASSWORD` |
| **云凭据** | `accessKeyId`、`secretAccessKey`、`AKIA`、`LTAI`（阿里云）、`SecretId`（腾讯云） |
| **应用密钥** | `appSecret`、`app_key`、`SECRET_KEY`、`JWT_SECRET`、`AES_KEY`、`SM4` |
| **三方服务** | `smtp`、`mail_password`、`wechat`、`alipay`、`dingtalk` |
| **内部地址** | `192.168.`、`10.`、`internal.`、`*.corp`、`vpn.` |
| **CI/CD** | `secrets.`、`DEPLOY_TOKEN`、`KUBECONFIG` |
| **文件类型** | `.env`、`config.*`、`*.bak`、`*.sql`、`id_rsa`、`.npmrc`、`.pypirc` |

## 四、执行步骤

### 步骤 1 · 定位组织与仓库
```bash
# 组织仓库列表
curl -s "https://api.github.com/orgs/<org>/repos?per_page=100" | grep -E '"name"|"description"'
```
判据：找到与目标业务相关的仓库（名字含系统名、portal、oa、edu 等）

### 步骤 2 · 代码搜索
浏览器打开 `https://github.com/search?type=code&q=<语法>`（**未登录时功能受限，登录后可用**）
判据：命中文件 + 出现真实值（不是 `your_password_here` 占位符）

### 步骤 3 · 历史提交挖掘（**最容易被忽略**）
密钥常被"删除"过，但还在历史里：
```bash
git clone --quiet https://github.com/<org>/<repo>.git /tmp/repo
cd /tmp/repo
# 搜历史里出现过 password 的提交
git log -S"password" --oneline --all | head -20
# 看某次删除的配置
git show <commit>:config/database.php
```
判据：历史提交里出现**真实**连接串/密钥

### 步骤 4 · 验证存在性（**只验证到能读即止**）
- 数据库连接串：**不连**（连生产库是越界行为），只在报告里记录"疑似有效连接串"
- 第三方 API Key：最多发 1 次鉴权请求确认有效，**不调用业务接口**
- 内部地址：用 `ping`/`curl -I` 确认是否可达（可达才写进报告）

## 五、判定标准

| 命中类型 | 算不算成果 |
|---|---|
| 真实数据库连接串（非占位符） | ✅ 高价值（但**不实测连接**） |
| 云 AK/SK 且验证有效 | ✅ 高价值（只调 1 次 `GetCallerIdentity` 类只读接口） |
| 内部系统地址 + 可访问 | ✅ 中高价值（可作为新攻击面） |
| 源码泄露（完整业务代码） | ✅ 中价值（可做代码审计找逻辑漏洞） |
| 只有占位符/示例值 | ❌ 不算 |
| 公开文档里的公开 key | ❌ 不算 |

## 六、证据要求

1. 搜索链接（含语法）+ 命中文件路径
2. 命中内容（密钥打码，只留前后各 4 位）
3. 验证记录（如调了一次只读接口，给请求与响应）

## 七、失败判据

- 组织下无公开仓库 → 转其他线索
- 搜到全是占位符/示例 → 放弃
- 只有 README 类文档 → 价值低

## 八、边界（红线）

- **只读公开仓库**，不 clone 私有库、不用他人 token
- 发现凭据后：**不批量使用、不外传、不在报告里放明文**
- 数据库连接串不实连（避免"越权访问生产库"）
- 涉及个人信息的仓库文件，只统计条数不下载

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 未登录搜代码 | GitHub 代码搜索未登录时能力受限，很多结果看不到 |
| 只看最新代码 | 密钥多半在历史提交里 |
| 把示例值当漏洞 | `password = "your_password"` 是模板 |
| 一上来连数据库 | 越界；且可能触发告警 |
