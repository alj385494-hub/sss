---
name: subdomain-takeover-hunt
description: 【侦察】子域接管：识别 CNAME 指向已释放云资源的悬空子域（GitHub Pages、Heroku、S3/OSS、Azure、CDN 等），判定"可接管"与"仅悬空"的区别，并给出只证明不抢占的正确做法
whenToUse: 子域枚举完成、需要对存量 CNAME 记录做一次悬空检查时；或发现子域返回云厂商"未配置/不存在"页面时
role: recon
category: 侦察
tags: [subdomain, takeover, cname, dangling, 子域接管]
enabled: true
---

# 子域接管

> 本质：**CNAME 指向了一个已释放的资源名，而那个资源名谁都能注册**。
> 判定关键不是"CNAME 指向外部"，而是"**那个外部资源当前无人认领**"。

## 一、哪些服务有接管风险

| 服务 | 悬空特征 | 接管方式 |
|---|---|---|
| GitHub Pages | 404 + "There isn't a GitHub Pages site here" | 建同名仓库并配置 Pages |
| Heroku | "No such app" | 注册同名 app |
| AWS S3 | `NoSuchBucket` | 注册同名 bucket |
| 阿里云 OSS | `NoSuchBucket` / `AccessDenied`（无主） | 建同名 bucket |
| Azure (`*.azurewebsites.net`/`cloudapp`) | 404 特定文案 | 建同名应用 |
| Vercel/Netlify | "DEPLOYMENT_NOT_FOUND" | 建同名项目 |
| 腾讯云 COS | `NoSuchBucket` | 建同名 bucket |
| 已废弃 CDN 回源 | 返回别的站点内容 | 视情况 |

## 二、执行步骤

### 步骤 1 · 收集 CNAME

```bash
# 对全部子域取 CNAME（含多级）
while read d; do
  c=$(dig +short CNAME "$d" | head -1)
  [ -n "$c" ] && echo "$d -> $c"
done < subs.txt | sort -u > cnames.txt
```

**重点**：指向**外部云服务域名**的（不是指向自己域名内部的）。

### 步骤 2 · 逐条判断"是否悬空"

```bash
# 直接访问该子域，看返回内容
curl -s -o /tmp/t.html -w "%{http_code}\n" "https://$d/"
grep -iE "there isn't a github pages site|no such app|NoSuchBucket|DEPLOYMENT_NOT_FOUND|not found" /tmp/t.html
```

| 现象 | 含义 |
|---|---|
| 云厂商"资源不存在"页 | ✅ **悬空**（可接管） |
| 云厂商"无权访问"页 | ⚠️ 资源存在但受限（通常不可接管） |
| 正常站点内容 | ❌ 有人认领 |
| 404 但是自建页 | ❌ 不是悬空 |

### 步骤 3 · 证明可接管（**只证明，不真抢占**）

正确做法：
1. 记录 CNAME 链 + 云服务返回的"未认领"响应
2. **在报告里写明**：该资源名当前无主，任何人注册同名资源即可控制该子域
3. **不实际注册**同名资源（那等于接管客户子域，属越界且可能被滥用）

若平台/客户要求实证，需先取得书面许可，且用**可逆方式**（挂一个无害标记页，事后立即释放）。

## 三、判定标准

| 结果 | 结论 |
|---|---|
| CNAME 指向云服务 + 返回"资源不存在" | ✅ 可接管（中高价值） |
| 能进一步证明可挂任意内容 | ✅ 高 |
| CNAME 指向自己域名内部 | ❌ 无接管风险 |
| 云服务返回 403/受限 | ⚠️ 一般不构成 |

## 四、证据要求

1. `dig CNAME` 完整链（含多跳）
2. 子域返回的"未认领"页面截图
3. 说明该云服务的接管前提（如"建同名 GitHub Pages 仓库"）
4. **明确写"未实际抢占"**

## 五、失败判据

- 全部 CNAME 指向自己域名 → 放弃
- 云端资源均有人认领 → 放弃
- 只有泛解析 → 放弃

## 六、边界（红线）

| 禁止 | 原因 |
|---|---|
| 实际注册资源接管子域 | 等于控制客户资产，严重越界 |
| 用接管挂钓鱼页/挂马 | 违法 |
| 抢注后索要赎金 | 违法 |

## 七、常见坑

| 坑 | 说明 |
|---|---|
| 只看 CNAME 不看响应 | 指向云服务 ≠ 可接管 |
| 把"泛解析指向 CDN"当悬空 | CDN 有记录就有人认领 |
| 忽略多级 CNAME | `a -> b -> c`，要看链尾 |
| 忘记看 AAAA | IPv6 也可能悬空 |
