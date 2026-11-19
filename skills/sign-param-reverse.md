---
name: sign-param-reverse
description: 【验证】签名参数逆向：识别 code/sign/mac 类签名鉴权，从前端 JS 定位算法（拼接规则、密钥、编码），本地复算验证，把"改参数就报错"变成可复现请求
whenToUse: 改参数后连环报错（ts/nonce/code/sign/mac 不能为空或不匹配），或接口要求 code 值但前端看不出生成逻辑时
role: exploit
category: 验证
tags: [sign, signature, reverse, js, mac, nonce, 签名, 逆向]
enabled: true
---

# 签名参数逆向

> 签名不是"防住你"，只是"让你算一遍"。算法几乎总在前端。

## 一、先判断是哪种鉴权

| 报错特征 | 类型 | 应对 |
|---|---|---|
| `非法请求：code值不能为空` / `sign不能为空` | **参数签名** | 本文主流程 |
| 改参数 → `时间戳有问题` → 改 ts → `nonce有问题` → 改 nonce → `mac有问题` | **ts+nonce+mac 签名** | 本文 + 注意 ts 时效 |
| `Authorization` 无效 | 令牌型 | 见 `session-acquisition` |
| `签名验证失败` 且响应含 `appKey` | 三方网关签名 | 找 appSecret |

**快速区分**：
```bash
# 只加一个 code 空值，看报错是否变化
curl -s "https://target/api/x" -H 'Content-Type: application/json' -d '{"code":""}'
# 若报"不能为空" → 参数签名，继续
```

## 二、定位算法（按命中率）

| 位置 | 怎么找 |
|---|---|
| **前端 JS bundle** | 搜 `sign`、`code`、`mac`、`md5`、`sha1`、`HmacSHA`、`CryptoJS`、`encrypt` |
| **构建产物** | `app.*.js`、`chunk-vendors.*.js`、`.js.map` |
| **小程序包** | 反编译后搜同样关键词 |
| **请求头** | 有时签名在头（`X-Sign`、`Timestamp`、`Nonce`） |
| **错误信息** | 报错里可能写"缺哪个参数" |

**常用搜索命令**：
```bash
grep -oE '.{80}(md5|sha1|HmacSHA|sign)\s*\(.{120}' app.js | head -20
grep -oE '[a-zA-Z_$]{1,4}\s*=\s*[a-zA-Z_$]{1,4}\s*\+\s*[a-zA-Z_$]{1,4}\s*\+\s*[a-zA-Z_$]{1,4}' app.js | head
```

## 三、还原拼接规则（四种常见形态）

| 形态 | 例子 | 复算方法 |
|---|---|---|
| **纯拼接 md5** | `md5(ts + nonce + secret)` | 找到三段来源；secret 常在 JS 里 |
| **排序拼接** | `md5(sorted(params) + secret)` | 注意排序规则（字典序/参数顺序） |
| **带 body** | `md5(method + path + body + ts)` | 注意 body 是否 JSON 序列化后参与 |
| **HMAC** | `HmacSHA256(data, secret)` | 注意输出编码（hex vs base64） |

**还原步骤**：
1. 找到签名函数定义（不是调用点）
2. 打印它的入参（浏览器断点 / 在页面里覆盖函数加 console.log）
3. 用同样入参在本地复算，与真实请求的签名**逐字符比对**
4. 一致 → 成功；不一致 → 检查编码/大小写/空格/排序

## 四、本地复算模板

```bash
# 纯 md5 拼接
SIGN=$(printf '%s' "${TS}${NONCE}${SECRET}" | md5sum | cut -d' ' -f1)

# 带密钥的 HMAC
SIGN=$(printf '%s' "${DATA}" | openssl dgst -sha256 -hmac "${SECRET}" | awk '{print $2}')

# 发送
curl -s "https://target/api/x" \
  -H 'Content-Type: application/json' \
  -H "X-Sign: ${SIGN}" -H "X-Ts: ${TS}" -H "X-Nonce: ${NONCE}" \
  -d '{"...":"..."}'
```

## 五、判定标准

| 检查 | 通过标准 |
|---|---|
| 签名可复算 | 本地算出的值 == 抓包里的值（逐字符） |
| 复算后请求可通过 | 返回业务数据，不再是"签名错误" |
| ts 时效 | 若校验时间窗，需用当前时间戳（不是抓包里的旧值） |

## 六、证据要求

1. 签名算法代码片段（JS 原文，密钥打码）
2. 抓包里的真实签名 + 本地复算结果（两个值并列展示一致）
3. 用自算签名调通的请求与响应

## 七、失败判据

- 前端只有调用没有实现（签名在服务端）→ 转找服务端下发的密钥接口
- 算法在 **WASM** 里且无 sourcemap → 成本过高，放弃
- 密钥是**一次性下发**且每次请求变化 → 不是硬编码签名，需先拿密钥接口
- 有强反调试（定时 debugger）→ 换真机/真浏览器，别硬肛

## 八、边界

- 复算签名**只用于验证接口可达性**，不做批量业务操作
- 不写自动化刷接口的脚本
- 若签名保护的是支付/下单，**只验证到"能调通查询"为止**，不执行交易

## 九、常见坑

| 坑 | 说明 |
|---|---|
| 用抓包里的旧 ts | 有时间窗校验时会失败，要用当前时间 |
| 编码不一致 | hex 全小写 vs 大写、base64 有无 padding |
| JSON 序列化差异 | 空格、字段顺序会影响 md5 |
| 只改一个参数就断言"需要签名" | 可能是缺必填参数导致的报错，先补齐参数 |
