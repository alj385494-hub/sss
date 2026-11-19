# dsh-tool-guardrail

把「工具权限 / 授权范围 / 数据量 / 审计」从 Prompt 约定升级成 **DSH 程序级机制**。

> 起因：一份外部审计建议说「目前最需要加强的不是继续增加技能数量，而是把权限、授权、任务调度和数据管理从 Prompt 约定提升为真正的程序级机制」。
> 这个插件就是那句话的落地。

---

## 它拦在哪一层

DSH 的工具执行管道（源码依据见 `docs/` 里的调研笔记）：

```
tools/pre-execute   ← 本插件在这里做审批（allow / deny / ask）
   ↓
ctx.tools.guard(fn) ← 本插件在这里做硬拒绝（单调，后续监听器翻不了案）
   ↓
tools/execute → 工具本体 → tools/post-execute
   ↓
tools/result        ← 本插件在这里记审计
```

`exec` 能拿到的东西（`dsh-tools/src/contracts.ts` 的类型定义）：

```ts
interface ToolExecutionInput {
  callId, rootCallId?, name, schema?, arguments: unknown,
  agent?: { id: SessionId },   // ← 只有 session id，没有 preset
  toolSet?, parent?, signal
}
```

**注意 `agent` 只有 id。** 想知道"这是哪个角色"要自己查：

```js
const session  = ctx.get('sessions').get(exec.agent.id)
const presetId = ctx.get('agentPresets').presetForSession(session)  // 'redteam-worker-recon'
```

---

## 六类规则

| 规则 | 作用 | 依据字段 |
|---|---|---|
| `toolDeny` | 无条件禁止某工具 | `exec.name` |
| `agentDeny` | 按角色禁止（**presetId 精确匹配**，拿不到才退回身份串） | `sessions` + `agentPresets` |
| `argMax` | 参数上限（如 `limit>1000` 直接拒，防一次拉全库） | `exec.arguments` |
| `argDeny` | 工具+参数条件（如 `data_proof.row_count>50000`） | `exec.arguments` |
| `approval` | 高危工具走**人工审批卡片**（`{kind:'ask'}`） | `tools/pre-execute` |
| `outOfScope` | 参数里的域名/IP 不在授权范围就拒 | `scope.json` |

---

## 安装

```bash
# 1. 放进 profile 的 node_modules
cp -r plugins/dsh-tool-guardrail ~/.dsh/profiles/desktop/node_modules/

# 2. 在 cordis.patch.yml 里挂上（注意必须用 - insert:，- id: 是修改已有条目的语法）
# - insert:
#     - id: tool-guardrail
#       name: dsh-tool-guardrail
#       config:
#         workspace: '你的工作区绝对路径'

# 3. 完全退出 DSH（含托盘）重启
```

**`config.workspace` 很重要**：插件要在这里找 `runs/tools/guardrail-policy.json` 和 `runs/tools/scope.json`。
不配也行——会自动探测（环境变量 `GUARDRAIL_WS` → cwd → 找一个下面有 `runs/tools` 的目录）。

---

## 配置

### `runs/tools/guardrail-policy.json`

```json
{
  "enabled": true,
  "mode": "observe",          // observe=只记录 / enforce=真拦
  "agents": {
    "recon": {                // 子串匹配 presetId
      "deny": ["redteam_score_hit", "redteam_webshell_add"],
      "reason": "信息收集角色只收面"
    }
  },
  "argMax": { "limit": 1000, "pageSize": 500 },
  "argDeny": [
    { "tool": "redteam_data_proof", "arg": "row_count", "gt": 50000,
      "reason": "疑似批量导出" }
  ],
  "approval": {
    "tools": ["redteam_webshell_add", "redteam_tunnel_add"],
    "reason": "高危动作需人确认"
  }
}
```

**改这个文件不用重启**（按 mtime 缓存）。

### `runs/tools/scope.json`

见 `runs/tools/scope.template.json`。要点：

- `targets.<靶标>.domains` 是**后缀匹配**（`<客户域名>` 覆盖 `www.<客户域名>`）
- `targets.<靶标>.ips` 支持 CIDR
- `excludeDomains` 放基础设施域名（github / crt.sh / npm …），永不判越界
- `allowLocal` 放行 `10.` / `192.168.` / `172.16-31.` / `127.` / `169.254.`
- `enforce: false` 只记录（审计里 `outOfScopeObserved`），`true` 才真拒

---

## 先 observe，再 enforce

**不要一上来就 enforce。** 推荐流程：

1. `mode: "observe"` + `scope.enforce: false` 跑一轮真实作业
2. 看 `runs/guardrail-audit.jsonl`：
   - `decision: "deny"` 但你觉得不该拦 → 规则配错了
   - `outOfScopeObserved` 出现正常域名 → scope 配少了或 exclude 配少了
   - `presetId` 一直是 null → `sessions`/`agentPresets` 服务没挂，`agentDeny` 在走 blob 兜底
3. 确认无误再切 `enforce`

审计日志样例：

```json
{"t":1795059418687,"tool":"redteam_score_hit","callId":"c1","mode":"enforce",
 "decision":"deny","rule":"agentDeny","matched":"recon",
 "reason":"信息收集角色只收面","presetId":"redteam-worker-recon"}
```

---

## 测试

```bash
# 逻辑单测（不需要 DSH、不需要重启）
node test/evaluate.test.mjs
```

覆盖：放行 / 工具黑名单 / 按角色拒绝（presetId 精确 + blob 兜底）/ 参数上限 / 工具+参数条件 /
observe 不拦 / enforce 真拦 / 空 exec 不崩。

**改代码后建议跑一次**，尤其改 `evaluate` 或正则时。

---

## 两条设计原则（都是踩坑换来的）

1. **插件自己绝不抛异常**：任何检查出错一律放行并留痕。护栏不能把正常工具搞挂。
2. **不给虚假的安全感**：`mode` 默认 `observe`；`verify` 类功能必须能报错。
   一个永远返回 ✅ 的工具比没有工具更坏。

---

## 已知限制

- `scope` 的域名/IP 是从 `exec.arguments` **递归提取字符串**得到的，深度 ≤4。
  参数里如果有大量非目标文本（比如整页 HTML），会产生较多误报候选——所以默认 `allowUnlisted: true`。
- 不含任务状态机 / 心跳 / 幂等：那部分 DSH 已经管进程，再做一层是重复造轮子。
