# DSH 更新 SOP（避免每次更新都手工重改插件）

> 背景：2026-11-13 → 11-14 的一次 `0.2.2-rc.1 → 0.2.2-rc.3` 更新，暴露了我们环境的 4 类脆弱点，
> 每次都靠手工发现+手工修。本文把这件事固化成「一条命令查全部 + 清单照做」。

---

## 0. 一句话流程

```bash
# 更新前
bash runs/tools/post-update-check.sh --save     # 确认当前无漂移，并把当前状态存为基线

# 更新后（重启 DSH 之后）
bash runs/tools/post-update-check.sh             # 一条命令列出所有漂移 + 每条的修复办法
```

有漂移时按输出里的 `修复:` 逐条做，做完确认状态正确再 `--save` 刷新基线。

---

## 1. 工具

| 文件 | 作用 |
|---|---|
| `runs/tools/dsh_state.py` | 采集/对比环境状态（asar 版本、bundles 顺序、patch 定制行、vendor 不变量、插件版本与 engines、技能数） |
| `runs/tools/dsh-baseline.json` | 基线快照（**已知良好状态**，`--save` 生成） |
| `runs/tools/post-update-check.sh` | 薄包装：跑对比 + 打印人工确认清单 |
| `runs/tools/dsh_state.py --json` | 输出当前状态（排查用） |
| `runs/tools/dsh_state.py --state-file X.json` | 用指定 JSON 当「当前状态」（测试/对比两份快照） |

退出码：`0` 无漂移，`1` 有漂移。

---

## 2. 检查项与对应的历史事故

| # | 检查项 | 历史事故（这就是为什么要查） | 修复动作 |
|---|---|---|---|
| 1 | **profile bundles 少了项** | rc.3 更新把 `@deepseek-ai/dsh-experimental-agent-team-profile` 从 bundles 移除 | `plugin_manager set_bundle` 重新启用；或从备份 `package.json` 回填 |
| 2 | **bundle 顺序变了** | squads(`@linxin666/dsh-agents`) 曾排在官方 agent-team 之前抢注册 `agentTeams` 服务，导致「智能体团队」显示异常 | 手改 `~/.dsh/profiles/desktop/package.json` 的 `dsh.profile.bundles` 顺序 |
| 3 | **cordis.patch.yml 定制行丢失** | `web-ui-browser-view`（与 dsh-inner-browser-use 重复注册 `browser_*`）、`web-ui-agents`（rc.3 上导入失败）都靠这行关掉 | 从 `cordis.patch.yml.bak-*` 回填 |
| 4 | **vendor 红队基座回归** | 插件升级会覆盖 `vendor/dsh-redteam-mode`，里面的 `cordis.patch.yml` 手工修复（删 `list-agents`、补 `internal-recon`）会丢 | `python runs/tools/fix-redteam-preset.py`，改完**完全退出 DSH（含托盘）**再启动 |
| 5 | **技能数下降** | `~/.dsh/skills` 被误删/改名 | 从 `runs/backup/dsh-preupdate-*/skills` 回拷 |
| 6 | **插件 engines 与 DSH 不兼容** | `@linxin666/dsh-agents@0.4.16` 在 rc.3 上 `import '@deepseek-ai/dsh-subagent/internal'` 失败（该子路径已移除）；npm 上 0.4.18 才是适配版 | 升级插件（`engines.dsh` 需覆盖当前版本）或禁用其行 |
| 7 | **核心包不再有 agent-team** | rc.3 把团队能力提为核心：`dsh-base` 里有 `agent-team`(maxTasks 256) + `tool-agent-team`，`dsh-web-app` 里有 `ui-agent-team` | 检查 `@deepseek-ai/dsh-agent-team` 是否还在 asar 内 |

---

## 3. 更新前必做

```bash
# 1) 备份 profile 定制
TS=$(date +%Y%m%d-%H%M%S); BK=~/dsh-preupdate-$TS; mkdir -p $BK
cp ~/.dsh/profiles/desktop/{package.json,pnpm-lock.yaml,cordis.patch.yml} $BK/
cp -r ~/.dsh/profiles/desktop/vendor/dsh-redteam-mode $BK/
cp -r ~/.dsh/skills $BK/
# 2) 存基线
bash runs/tools/post-update-check.sh --save
```

---

## 4. 更新方式（本机实测）

界面更新（设置→关于）**实际不会重启**，会卡在下载后不安装。可靠做法：

1. 关掉 DSH 里所有窗口
2. 从 nightly 源下载安装包并校验 sha512
   `https://download.deepseek.com/dsh-desk/feeds/win-x64/nightly.yml`（文件名/大小/sha512 都在里面）
3. **静默安装**：`"<安装包>" /S`
4. 从**独立进程**启动安装脚本，否则 `taskkill /T` 会把脚本自己一起杀掉
   （用 `Invoke-CimMethod Win32_Process Create` 创建，父进程变成 `WmiPrvSE.exe` 就不会连坐）

---

## 5. 更新后

```bash
bash runs/tools/post-update-check.sh
```

再人工确认（脚本看不到的）：

- 设置→插件：`include:agent-team` / `tool-agent-team` / `ui-agent-team` 是否 active 且无 diagnostic
- 团队功能：**rc.3 起 Team 默认关闭**，在根会话的「模型与推理等级」菜单里开「启用智能体团队协作」
- 插件市场：`indexes` 默认 `[]`，没配索引源时 Discover 页为空属正常
- 记忆系统 `mnemon_status`

---

## 6. 什么时候该 `--save`

- 你**故意**改了插件/顺序/patch，并已确认工作正常
- 升级了社区插件（版本会变，属正常信息，但基线要跟上）

不 `--save` 的后果：每次检查都会重复报同一项，反而让人忽略真正的漂移。
