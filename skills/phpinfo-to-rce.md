---
name: phpinfo-to-rce
description: 【验证】phpinfo 与 PHP 信息泄露的后利用：从 phpinfo 页面提取绝对路径、扩展、临时目录、配置项与被禁函数，判断能否升级为文件读取/包含/写马之外的"可提交"成果（**不做写马**）
whenToUse: 站点暴露了 phpinfo()/phpinfo 页，需要判断这个泄露能否升级为更有价值的发现时
role: exploit
category: 验证
tags: [phpinfo, php, info-disclosure, 配置泄露, 后利用]
enabled: true
---

# phpinfo 的后利用

> phpinfo 本身通常是**低危（配置错误级）**。
> 是否值得继续，取决于它能不能给出**可用于下一步的具体路径与配置**。

## 一、从 phpinfo 里能拿到什么

| 信息 | 用途 |
|---|---|
| `DOCUMENT_ROOT` / `SCRIPT_FILENAME` | **绝对路径**（路径穿越、包含、日志投毒的基准） |
| `open_basedir` | 是否限制了目录范围 |
| `disable_functions` | 哪些函数被禁（判断可行性） |
| `upload_tmp_dir` / `sys_temp_dir` | 临时文件位置 |
| 加载的扩展（`gd`/`imagick`/`ffmpeg`/`soap`） | 可利用的解析类漏洞 |
| `allow_url_include` / `allow_url_fopen` | 远程包含是否可行 |
| DB 连接配置（有时泄露） | 凭据线索（**不实连**） |
| Session 保存路径 | session 文件位置 |
| `SERVER_SOFTWARE` / 版本 | 精准 Nday |

## 二、可升级的方向（按利用价值排序）

### 1. 路径泄露 → 目录穿越/文件读取

拿到 `DOCUMENT_ROOT=/www/wwwroot/xxx` 后，配合已有的文件读取参数：
```bash
curl -s "https://target/download?file=../../../../www/wwwroot/xxx/config/db.php"
```
**判据**：读到 PHP 源码（不是执行结果）。

### 2. 版本/扩展 → 精准 Nday

| 看到 | 可能 |
|---|---|
| PHP 5.x + 某扩展旧版 | 对应 CVE |
| `imagick` 旧版 | ImageMagick 漏洞 |
| `soap` 开启 | SSRF/XXE 面 |

### 3. 配置不当 → 信息泄露升级

`display_errors=On` + 触发报错 → 报错里含 SQL/路径/源码片段。

### 4. 临时目录 → 文件包含（**谨慎，需已有包含点**）

已知 `upload_tmp_dir` 与一个文件包含参数时，可尝试包含上传的临时文件。
**仅在已确认存在包含参数时尝试，且上传内容为无害标记。**

## 三、判定标准

| 结果 | 结论 |
|---|---|
| phpinfo 能读出绝对路径，且配合已有洞读到源码 | ✅ 中（升级成功） |
| phpinfo 泄露 DB 凭据且有效 | ✅ 中高 |
| 只有 phpinfo 页面本身 | ⚠️ 低（配置错误级，多数平台判低） |
| phpinfo + 无任何可用配置 | ❌ 不提交 |

## 四、证据要求

1. phpinfo 页面 URL + 关键片段截图（路径/版本/配置）
2. 升级后的利用请求与响应（如读到的源码片段）
3. 说明"phpinfo 在其中起什么作用"（不能只贴 phpinfo）

## 五、失败判据

- phpinfo 只有基本信息（版本），无路径/无扩展 → 低价值，不投入
- `open_basedir` 严限且无绕过 → 放弃
- 没有可配合的其他洞 → 记录后放弃

## 六、边界（红线）

| 禁止 | 原因 |
|---|---|
| 写 webshell / 上传马 | 越界 |
| 用 phpinfo 做 DoS | 影响业务 |
| 实连泄露的数据库 | 越界 |
| 把 phpinfo 单独当"高危"提交 | 会被判定夸大 |

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 把 phpinfo 当成果 | 单独几乎总是低危 |
| 不看 `disable_functions` | 决定后续可行性 |
| 忽略版本→Nday 匹配 | 路径泄露之外最实用的用法 |
| 忘记 phpinfo 可能有多个入口 | `/info.php` `/phpinfo.php` `/test.php` `/i.php` |
