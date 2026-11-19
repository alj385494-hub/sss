# DSH 工具执行管道与插件扩展点（源码调研，2026-11-19）

> 来源：`<DSH安装目录>/node_modules/@deepseek-ai/`
> DSH 版本：0.2.2-rc.3（包内 version 字段）
> 调研方法：读 `dsh-tools/README.md` + 统计 338 个包对 `exec.*` 的实际使用 + 读 `dsh-tool-call-timeout-policy/lib/index.js` 全文
> **结论可直接用于写拦截插件，不是推测。**

## 一、工具执行的管道（洋葱模型）

```
tools/pre-execute      ← 可扩展的 allow / deny / ask 门（可重排）
   ↓
ctx.tools.guard(fn)    ← 单调同步 guard：返回字符串 = 拒绝，且**不可翻案**
   ↓
tools/execute          ← 包装 dispatch（timeout / retry / metrics），唯一可替换 exec.signal
   ↓
工具本体（tool definition 的 execute）
   ↓
tools/post-execute     ← 可检查/替换内容或值、block with feedback、附加上下文
   ↓
finalizeContent        ← 工具自有的最终内容变换
   ↓
tools/result           ← 只读观察冻结后的最终结果
```

原文（`dsh-tools/README.md` L112 / L137）：
> `tools/pre-execute` (extensible allow/deny/ask) → registered monotonic guards → `tools/execute` (around-dispatch wrappers) → `tools/post-execute` (inspect/replace, attach context) → definition-owned `finalizeContent` → the observe-only `tools/result` event.
>
> `tools/pre-execute` is the reorderable allow/deny/ask gate; `ctx.tools.guard()` adds monotonic owner policy after it; `tools/execute` wraps normalized canonical dispatch for timeout, retry, or metrics; `tools/post-execute` may replace content or value, block with feedback, or attach ordered contexts; `tools/result` observes the immutable final outcome.

## 二、`exec` 对象的字段（从全量源码统计，次数为使用频次）

| 字段 | 次数 | 用途 |
|---|---|---|
| `exec.signal` | 161 | AbortSignal（取消） |
| `exec.agent` | 148 | **agent 对象**（有 `.id` / `.session` / `.ctx` / `.options` / `.model`） |
| `exec.name` | 50 | **工具名** |
| `exec.parent` | 24 | 父调用 |
| `exec.callId` | 24 | **调用 ID**（审计用） |
| `exec.arguments` | 18 | **参数对象**（已冻结） |
| `exec.rootCallId` | 13 | 根调用 ID（子调用链） |
| `exec.toolSet` | 10 | 解析后的工具集 |
| `exec.token` | 7 | 关联 token |
| `exec.schema` | 5 | 工具 schema |

`agent` 对象常用字段：`agent.session`(310) / `agent.id`(116) / `agent.ctx`(39) / `agent.options`(18) / `agent.model`(12)

## 三、四种拦截方式的写法（都有真实代码依据）

### ① 最简拒绝：`ctx.tools.guard`（同步、单调、不可翻案）

```js
childCtx.tools.guard((exec) =>
  blocked
    ? `拒绝理由：${exec.name} 不在本角色白名单内`   // 返回字符串 = 拒绝
    : void 0                                        // 返回 undefined = 放行
);
```
出处：`dsh-subagent/lib/index.js:1069`（真实用法）

**特点**：同步、简单、**拒绝后没有后续监听器能翻案**。适合硬白名单。

### ② 灵活决策：`tools/pre-execute`（allow/deny/ask）

支持三态，`ask` 会走人工审批。签名未在 README 给出确切参数，需实测确认（见「待验证」）。

### ③ 包装：`tools/execute`

```js
ctx.on("tools/execute", async (exec, next) => {
  const result = await next();          // 调用下游
  return result;                        // 可替换结果
});
```
出处：`dsh-tool-call-timeout-policy/lib/index.js`（全文读过）

### ④ 观察：`tools/result`（只读，审计用）

```js
ctx.on("tools/result", (exec, result) => { /* 记审计日志 */ });
```
出处：`dsh-subagent/lib/index.js:1070`

## 四、插件最小骨架

```js
const name = "my-plugin";
const inject = ["tools"];               // 依赖 tools 服务
function apply(ctx) {
  ctx.tools.guard((exec) => /* ... */);
}
export { name, inject, apply };
```

`package.json` 关键字段：
```json
{
  "name": "@yourscope/dsh-my-plugin",
  "type": "module",
  "main": "lib/index.js",
  "peerDependencies": {
    "@deepseek-ai/dsh-tools": "0.2.2-rc.3",
    "@deepseek-ai/cordis": "~4.1.0"
  }
}
```

挂载：在 profile 的 `cordis.patch.yml` 里加
```yaml
- name: '@yourscope/dsh-my-plugin'
```

## 五、这能解决什么 / 不能解决什么

| 需求 | 能否 | 靠哪个钩子 |
|---|---|---|
| 工具执行层拦截（改配置做不到的） | ✅ | `guard` / `pre-execute` |
| 按 agent / 角色区分工具权限 | ✅ | `exec.agent` |
| 程序级审批（人工确认才放行） | ✅ | `pre-execute` 返回 `ask` |
| 拒绝不可被后续规则翻案 | ✅ | `guard`（README 明说 monotonic） |
| 检查参数（如导出条数阈值） | ✅ | `exec.arguments` |
| 结果脱敏 / 替换 | ✅ | `post-execute` |
| 审计日志（哪个 agent 调了什么） | ✅ | `tools/result` |
| 任务状态机 / 心跳 / 幂等 | ❌ | DSH 已管进程，不该重做 |

## 六、待验证（写代码前必须实测）

1. `tools/pre-execute` handler 的**确切参数与返回值格式**（README 只写了 allow/deny/ask 概念）
2. `exec.agent` 里如何拿到**当前 agent 的 preset id**（`redteam-worker-recon` 等）——`agent.options` 可能是入口，未确认
3. `tools/result` 的 result 结构

**验证方式**：先写一个「探针插件」，把 `exec` 与 `result` 的结构 dump 到文件，重启后读真实数据，再写正式逻辑。
**不猜字段名。**
