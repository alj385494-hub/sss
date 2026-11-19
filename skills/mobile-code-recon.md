---
name: mobile-code-recon
description: 【侦察】移动端与代码泄露侦察：APK/IPA/小程序提取 API 与密钥、GitHub/Gitee/GitLab 代码泄露、前端 SourceMap（只取公开线索）
whenToUse: 靶标有 APP/小程序/H5，或需要从公开代码仓库/前端包找接口、密钥、内网地址时
role: recon
category: 侦察
tags: [mobile, apk, code-leak, api]
enabled: true
---

# 移动端 / 代码泄露侦察

> 只使用公开可获取的安装包/仓库/前端资源；不破解、不盗版、不碰与靶标无关的第三方代码。发现密钥先记录，不直接使用。

## 前置与工具

| 工具 | 用途 |
| --- | --- |
| `jadx` / `apktool` | APK 反编译、资源/Manifest |
| `MobSF`（可选） | 静态/动态分析 |
| `gitleaks` / `git-secrets` | 仓库密钥扫描 |
| `curl` / `browser-automation` | 前端 JS/SourceMap、小程序包 |
| `fofa-recon` / `deepseek-web-intel` | 公开资产与情报 |

## Android / iOS

```bash
# APK：先看 Manifest、字符串、assets、native lib
jadx -d runs/apk-<name> app.apk
apktool d app.apk -o runs/apk-<name>-smali
grep -RInE 'https?://|api[_-]?key|secret|token|access[_-]?key' runs/apk-<name> | head -100
```

- 关注：API base URL、内网地址、AK/SK、推送/地图/支付 Key、WebView 入口、证书绑定；
- iOS：`class-dump`/`strings`/`plutil` 看 Mach-O 与 Info.plist；不做越狱设备操作；
- 小程序：从缓存/包体提取 `app-service.js`、`wx.config`、request 域名；只抓公开包。

## 代码泄露

- GitHub/Gitee/GitLab 搜索：单位名、域名、项目名、`internal`、`jdbc:`、`AKID`、`password`；
- 重点：CI 配置（`.gitlab-ci.yml`、`Jenkinsfile`）、`.env`、`config.*`、`docker-compose`、测试脚本；
- 命中密钥只记录来源与截图，不直接登录；需要验证时先 `redteam_scope_check` 并走用户确认。

## 前端 / SourceMap

- JS 里找 `baseURL`、`/api/`、`/v2/`、`/internal/`、WebSocket；
- `.map` 还原源码，找接口与硬编码密钥；
- 结果写进资产 `test`/`surface`，接口清单落 `runs/`。

## 证据与落库

- 资产：`redteam_asset_add` / `redteam_batch kind=assets`（APP 后端域名/IP、小程序 API）；
- 线索：`redteam_asset_test` 的 `surface` 写接口/密钥/内网地址；
- 归属：ICP/证书/页脚/单位名，按 `asset-correlation`；
- 不把密钥明文写进报告/会话；按凭据规范落库。

## OPSEC 与边界

- 只下载公开包/公开仓库；不破解付费应用、不盗用第三方代码；
- 不对生产 API 做未授权批量请求；验证前先 scope check；
- 第三方代码/供应商资产不在范围只记线索；
- 不把个人开发者仓库当靶标资产，除非能证明归属。

## 交接

回报：APP/小程序入口、API base、泄露的密钥类型（不贴明文）、可用接口、归属证据、未覆盖平台；`needs` 写清缺的工具/授权。

---

## 加固包（360/梆梆/爱加密）怎么取证（2026-11-14 实测）

看到 `libjiagu.so` / `com.stub.StubApp` / `QHClassLoader` 即加固。**不要脱壳**（超出常规授权边界），
但加固**不影响以下四处**，证据全在这里：

1. **`resources.arsc`** —— 字符串资源常含 SDK 的 key/secret（脚本 `arsc_parse.py`）；
2. **`AndroidManifest.xml`（二进制 AXML）** —— meta-data 高密度堆着 SDK 密钥（脚本 `axml_dump.py`）；
3. **`assets/`** —— 例 `ShareSDK.xml` 直接写微信 AppId/AppSecret；
4. **`lib/*.so` + `classes.dex` 的 `strings`** —— 域名、路径、常量。

判据：拿到值必须**实测能换 token**才算漏洞；公开 SDK 的 appId（高德/华为 HMS）不算。
实测：<客户域名> APK（360 加固、dex 纯壳）靠 arsc+AXML+assets 拿到 3 组可用密钥，dex 一行没读。
> 工具对照：arsc/AXML 解析是业界标准做法，可对照 androguard（arsc/axml parser）、pyaxmlparser、
> androguard/axml-parser（https://github.com/androguard/axml-parser 、https://github.com/appknox/pyaxmlparser ）。
> 我们的 `arsc_parse.py`/`axml_dump.py` 是零依赖等价实现（不装第三方包）。

