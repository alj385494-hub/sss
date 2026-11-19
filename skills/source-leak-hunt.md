---
name: source-leak-hunt
description: 【侦察】源码与配置泄露：探测 .git/.svn/.hg/.DS_Store/.env/备份包/IDE 配置，用文件特征确认是否真泄露（而非 SPA 回落页），并判断泄露的内容是否含凭据与源码
whenToUse: 站点疑似有历史遗留的版本库或备份文件，或需要从泄露源码里找硬编码凭据/接口清单时
role: recon
category: 侦察
tags: [source-leak, git, svn, env, backup, 源码泄露]
enabled: true
---

# 源码与配置泄露

> 判据只有两条：**能读到真实文件内容**，以及**内容里有敏感东西**。
> 大量"泄露"其实是 SPA 回落页（200 + 首页 HTML）。

## 一、探测清单

### 版本库
```
/.git/HEAD           /.git/config        /.git/index
/.svn/entries        /.svn/wc.db         /.svn/pristine/
/.hg/requires        /.bzr/README
```

### 环境与配置
```
/.env                /.env.bak           /.env.local
/config.php          /config.js          /application.yml
/web.config          /.htaccess          /nginx.conf
```

### 备份包
```
/www.zip   /wwwroot.zip  /backup.zip  /site.tar.gz  /db.sql
/index.php.bak  /index.jsp~  /config.php.swp
/1.zip  /www.rar  /web.7z
```

### IDE 与工程文件
```
/.idea/workspace.xml   /.vscode/settings.json
/composer.json  /composer.lock  /package-lock.json
/.DS_Store     /Thumbs.db
```

## 二、判定"真泄露"（关键，避免假阳性）

| 检查 | 真泄露 | 假阳性 |
|---|---|---|
| 响应体 | `.git/HEAD` 返回 `ref: refs/heads/master` | 返回首页 HTML（SPA 回落） |
| 响应体 | `.env` 返回 `KEY=VALUE` 行 | 返回 404 页面/登录页 |
| 长度 | 明显小于首页 | 与首页长度一致 |
| Content-Type | `text/plain`、`application/octet-stream` | `text/html` |

> ⚠️ **"长度明显小于首页"这一条单独用会误判**，见下节四种假阳性。长度只能当辅助信号。

```bash
# 一条命令看是不是真文件
curl -s "$U/.git/HEAD" -w "\n[%{http_code} %{size_download} %{content_type}]\n"
```

### 2.1 必须逐 host 实测基线，四种假阳性形态（实战）

同一个靶标的不同站点会给出**四种完全不同的"假命中"**。任何一个"非 404 即命中"的扫描器都会全错：

| 形态 | 响应特征 | 如何识破 | 实例（2026-11，某高校） |
|---|---|---|---|
| **① 鉴权墙** | 任意路径回 `401` + 框架 JSON | body 是 `{"status":401,...}`，不是文件 | Spring Boot：`camanage` 18 条路径全 401 |
| **② SPA 回落** | `200` + 与首页几乎同尺寸 | 与首页 body 尺寸相差 <0.1% | `journals`：95114B vs 首页 95138B |
| **③ 软错误页** ⚠️ | **`200` + 体积远小于首页** + `Content-Type: text/html` | **按长度判会误判成真泄露**；必须看 body 是应用错误模板 | VAppServer：`/.git/HEAD` 回 `200/589B`，body 是 `<title>error</title>…遇到错误啦` |
| **④ catch-all 首页** | `200` + 与首页同尺寸（可能是几 MB） | 体积巨大 + 就是首页本身 | `equip`：任意路径回 `200/7249019B`（首页 7249025B） |

**正确做法**：每个 host 先请求一个随机不存在路径取基线（`状态码|长度`），之后所有结果与基线比对；**同时**用 `grep -c` 确认 body 里有没有 `.git/HEAD` 该有的内容特征词（`ref:` / `KEY=`）。

```bash
rnd="/zz-not-exist-$RANDOM.html"
base=$(curl -s "$U$rnd" -o /dev/null -w "%{http_code}|%{size_download}")
# 命中判定：非 404 且长度 != 基线 且 body 无 HTML 模板特征
```

> **③ 软错误页最容易骗人**：它同时满足"200"、"比首页小得多"、"text/html"（后者本表已列为假阳性特征，但很多人只看前两条）。判据应改为：**body 必须以该文件的真实格式开头**（`.git/HEAD` 以 `ref:` 开头，`.env` 以 `KEY=` 开头），否则一律不算。

## 三、.git 的完整利用链（有就值钱）

```bash
# 1. 确认可读
curl -s "$U/.git/HEAD"

# 2. 用工具 dump（git-dumper / GitHack）
python3 git-dumper.py "$U/.git/" ./dump

# 3. 历史审计（找被删的密码）
cd dump && git log --all --oneline | head -50
git log -S"password" --all --oneline
git show <commit>:config/database.php

# 4. 分支与 stash
git branch -a
git stash list
```

**价值排序**：配置里的连接串/密钥 > 业务源码（可审计逻辑漏洞）> 已删除的历史文件

## 四、.svn / .DS_Store

| 目标 | 方法 |
|---|---|
| `.svn/wc.db` | SQLite，`SELECT * FROM NODES` 拿完整文件列表 |
| `.svn/entries` | 旧版格式，直接含文件清单 |
| `.DS_Store` | 解析后得到目录内文件名列表 |

拿到清单后**逐个文件去请求**（很多文件不对外，但清单本身有价值）。

## 五、判定标准

| 结果 | 结论 |
|---|---|
| .git 可 dump + 历史含凭据 | ✅ 高 |
| .env 泄露数据库连接串 | ✅ 高 |
| 备份包可下载且含源码 | ✅ 中高 |
| 只拿到 `.DS_Store` 文件清单 | ⚠️ 低（信息泄露级） |
| 返回 SPA 首页 | ❌ 假阳性 |

## 六、证据要求

1. 请求 + 响应片段（证明是真文件，不是回落页）
2. 泄露内容里的敏感项（连接串/密钥，**打码**）
3. 说明影响：能拿到什么、是否含凭据

## 七、失败判据

- 全部路径返回同一份 HTML → SPA 回落，放弃
- .git 存在但 `objects` 不可读 → 无法还原，只记录
- 备份包 404

## 八、边界

- **只读**：不往版本库里写、不提交
- 数据库连接串**不实连**
- 源码里的个人信息只统计不摘录
- 下载的 dump 用完删除

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 只看 200 不看内容 | SPA 全部路径都 200 |
| 忘记试二级路径 | `/static/.git/`、`/app/.git/` 也有 |
| .git 只差 objects | 只有 HEAD/config 也值得记 |
| 忽略 `.svn/wc.db` | 它比 entries 信息更全 |
