---
name: hardcoded-credential-hunt
description: 【验证】前端与客户端硬编码凭据挖掘：从 JS bundle、sourcemap、小程序包、APK、桌面客户端里找写死的口令、密钥、AppSecret、AES key/IV，含定位手法与"算不算漏洞"的判定
whenToUse: 目标是 SPA/小程序/APP/桌面客户端，或需要证明"凭据在客户端可见"时；也用于解释为什么某个加密可被还原
role: exploit
category: 验证
tags: [hardcoded, credential, js, secret, sourcemap, appsecret, 硬编码]
enabled: true
---

# 硬编码凭据挖掘

> 客户端能拿到的东西，等于公开。问题不是"藏得深不深"，而是**别人能不能拿到并复用**。

## 一、什么时候用

- 页面是 SPA / 小程序 / Electron / APK，登录或接口加密在**前端完成**
- 加密请求体（AES/SM2/SM4）但密钥来自前端
- 有 `sourcemap`（`.js.map`）可还原源码
- 接口报错里出现 `appkey`、`sign` 字样

## 二、去哪找（按命中率排序）

| 位置 | 怎么取 | 常见内容 |
|---|---|---|
| **JS bundle** | F12 → Sources → 全局搜关键词 | `appSecret`、`AES_KEY`、`password:` |
| **sourcemap** | 试 `xxx.js.map`、`/static/js/*.map` | 原始源码 + 注释 + 内网地址 |
| **webpack runtime** | 搜 `webpackJsonp`、`__webpack_require__` | 模块清单（帮你找隐藏页面） |
| **HTML 注释/表单默认值** | `view-source:` | 测试账号、默认口令 |
| **小程序包** | 反编译 `.wxapkg`（工具另说） | 签名算法、AppSecret |
| **APK** | `apktool`/`jadx` | 硬编码 key、内网域名 |
| **桌面客户端** | 安装目录 `resources/app.asar`、`config.ini` | 服务器地址、更新密钥 |

## 三、关键词表

```
password  passwd  pwd  pass
secret  appSecret  app_secret  clientSecret
key  apikey  api_key  accessKey  access_key
token  jwt_secret  SECRET_KEY
aes  aesKey  iv  sm2  sm4  privateKey
jdbc:  mongodb://  redis://
internal  inner  corp  192.168  10.
```

## 四、执行步骤

### 步骤 1 · 拉取全部前端资源
```bash
# 主页面引用的 js
curl -s <url> | grep -oE 'src="[^"]+\.js' | cut -d'"' -f2 | sort -u
# 逐个下载后统一 grep
grep -rniE "appsecret|aeskey|password" ./js/
```
判据：命中且值是**具体字符串**（不是 `""`、不是 `your_key`）

### 步骤 2 · 判断密钥用途
| 用途 | 能否构成漏洞 |
|---|---|
| 前端加密**请求体**的 AES key | ✅ 能解/能伪造请求 |
| **签名**算法 + 密钥 | ✅ 能自算签名 → 越权测试可能 |
| 仅用于**本地存储**加密 | ⚠️ 价值低 |
| 三方 SDK 的公开 appid | ❌ 不算（公开值） |
| 后端 → 前端的 RSA 公钥 | ❌ 公开值，需配套私钥才算问题 |

### 步骤 3 · 验证（只读）
- 有可复算的签名/加密：**自己算一次**，用算出结果调用一个需要鉴权的只读接口
- 判据：接口返回业务数据（不是签名错误）
- **不写操作**：不改数据、不下单

## 五、判定标准

| 命中 | 结论 |
|---|---|
| 硬编码口令能登录进后台且后台有敏感数据 | ✅ 高价值 |
| 硬编码 AES key 能解密响应并读到他人数据 | ✅ 高价值 |
| 硬编码签名密钥能自算签名调通接口 | ✅ 中高价值 |
| 只有 appid/公开配置 | ❌ 不算漏洞 |
| 硬编码的是测试环境地址 | ⚠️ 低价值（可作线索） |

## 六、证据要求

1. 密钥所在文件的路径 + 片段（**密钥本身打码**，只留 4 位）
2. 用途说明（加密/签名/登录）
3. 验证记录：自算结果与官方响应一致 / 用该密钥成功调通 1 次只读接口

## 七、失败判据

- 搜到的全是占位符或公开 appid → 放弃
- 密钥是后端下发的一次性值（每次请求变化）→ 不是硬编码
- 只有混淆代码且无 sourcemap、无行为线索 → 成本高于收益，转其他面

## 八、边界

- 只读验证；不改数据、不下单、不登录他人账号
- 提取到的密钥只在本地验证、不外传；报告内打码
- 反编译只针对**公开可下载**的客户端，不破解付费/授权内容
