---
name: google-dorks-catalog
description: 【侦察】搜索引擎语法目录：按"找后台/找文件/找泄露/找子域/找报错/找设备"六类常用 dork 语法，含中文站适配与"为什么要看搜索结果第 2 页以后"
whenToUse: 需要从公开搜索引擎找目标暴露面（后台入口、敏感文件、报错页、设备面板）时
role: recon
category: 侦察
tags: [dorks, google, search, osint, 搜索引擎]
enabled: true
---

# 搜索引擎语法目录

> dork 的价值不在"多"，而在**针对目标特点选对那一类**。
> 一条精准 dork 胜过一百条泛化 dork。

## 一、六类 dork

### 1. 找后台/管理入口

```
site:<domain> inurl:admin
site:<domain> inurl:login  inurl:manage
site:<domain> intitle:"管理后台"
site:<domain> intitle:"登录" inurl:system
site:<domain> inurl:console  intitle:@"控制台"
```

### 2. 找敏感文件

```
site:<domain> ext:env  OR ext:ini  OR ext:conf
site:<domain> ext:sql  OR ext:bak  OR ext:zip  OR ext:rar
site:<domain> ext:log
site:<domain> ext:swp  OR ext:DS_Store
site:<domain> filename:web.config
```

### 3. 找泄露内容

```
site:<domain> "password" ext:txt
site:<domain> "jdbc:mysql"
site:<domain> "内部" "机密"
site:<domain> "身份证" "手机号"      ← 找含 PII 的页面/文件
```

### 4. 找子域与旁站

```
site:<domain> -www
site:*. <domain>
site:<domain> inurl:test  OR inurl:dev  OR inurl:uat
```

### 5. 找报错/调试页

```
site:<domain> "SQL syntax" OR "ORA-" OR "Warning: mysql"
site:<domain> "Whitelabel Error Page"
site:<domain> intitle:"phpinfo()"
site:<domain> "Index of /"          ← 目录列表
```

### 6. 找设备面板/中间件

```
site:<domain> intitle:"Login" "RouterOS" OR "H3C" OR "华为"
site:<domain> intitle:"宝塔" OR "BT-Panel"
site:<domain> intitle:"Zabbix" OR "Grafana" OR "Jenkins"
site:<domain> intitle:"Webmin" OR "phpMyAdmin"
```

## 二、中文站适配

| 差异 | 说明 |
|---|---|
| 搜索引擎 | 中文站用 **Bing / 百度 / 搜狗**，Google 索引不全 |
| 标题词 | 用「管理后台」「系统登录」「后台管理」，不用 "admin panel" |
| 文件类型 | 中文站常用 `rar`/`7z`，不只 `zip` |
| 备案号 | `site:<domain> "ICP备"` 可找同主体其他站 |

## 三、使用原则

| 原则 | 说明 |
|---|---|
| **先窄后宽** | 先用 `site:` 限定，再加 `inurl:`/`ext:` |
| **看第 2 页以后** | 高价值结果常被首页导航挤到后面 |
| **换引擎交叉** | Google/Bing/百度 结果差异大，都试 |
| **结果只是线索** | dork 找到的要**人工访问确认**，不能直接当发现 |
| **记录原始 dork** | 报告里要写清用的哪条语法（可复现） |

## 四、判定标准

| 结果 | 价值 |
|---|---|
| 找到未在子域列表里的后台入口 | ✅ 高 |
| 找到含 PII 的公开文件 | ✅ 高 |
| 找到报错页/phpinfo | ⚠️ 中（多为配置错误级） |
| 只找到官网首页 | ❌ 无价值 |

## 五、失败判据

- 该域名无索引（新站/被封）→ 换 Bing/百度
- 全部结果为官网正常页 → 放弃

## 六、边界

- 只搜公开索引，不做批量爬取
- 找到含个人信息的内容**只记录存在性，不下载**
- 不使用黑帽 SEO 手段

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 只用 Google | 中文站 Google 索引差 |
| dork 太宽 | 几千结果，全是官网 |
| 不看结果日期 | 老页面可能已下线 |
| 把搜索结果页当证据 | 必须访问原页面并截图 |
