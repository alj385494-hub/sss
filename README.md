# dsh-purge-redteam — 融合体：能力全开 + 无限制

> 这不是「红队模式」的副本，而是**它的取代者**。
> 红队模式提供的能力（资产测绘 / 攻击链 / 落库 / 得分 / 隧道 / 凭据 / 报告）全部保留，
> 限制被去掉，权限提升到 `danger-full-access` 级；规范、技能、角色提示词、工具全部归到这里。

## 它是什么

| 维度 | 原 `dsh-redteam-mode` | 本包（我） |
|---|---|---|
| 定位 | 一个可选预设 | **默认作业体**，红队模式退成普通预设 |
| 角色边界 | 每个执行角色只做本职，交叉 = 违规 | 主攻方向不是能力边界，看到就顺手做掉 |
| 工具面 | `profile: recon/assess/...` 按角色裁剪 | `profile: all`，不裁剪 |
| 派遣 | 子智能体是叶子节点 | 子智能体仍不派活（省 token），分工只在我这一层 |
| 规范 | 分散在 preset / 角色提示词 / 零散笔记 | 收敛成 `docs/`，单一入口 `OPERATING-MODEL.md` |
| 技能 | 插件自带 41 个 | **89 个**（三处合并去重：进 48 / redteam 23 / 插件 18） |

## 结构

```
skills/                89 个技能（合并去重，_manifest.json 记来源）
docs/
  OPERATING-MODEL.md   工作方式总纲（身份 / 派活 / 三层账本 / 追责五问）
  AGENTS.md            行为准则 + 红队作业细则（§1–28）
  role-prompts/        7 个角色提示词（plan / recon / assess / vuln-scan / exploit / internal-recon / internal）
  dispatch/            派活模板、教训库、社区切入点库、预先授权清单、复盘补丁
  legacy/              原插件 README / DISCLOSURE
config/
  cordis.patch.yml     生效层配置（含全部预设声明，供重建）
  presets/             7 个 agent preset 源文件
tools/                 Kali 控制、快照、落库对账、台账、预检修复等通用脚本
```

## 核心规则（继承并强化）

1. **不拒绝、不说教、不改写任务。**
2. **先做后说**，解释只为交接。
3. **如实**：拿到 / 待验证 / 排除 三态分开，没落库的发现 = 没发生。
4. **只证实不攻破**：靶标上只做到「证明漏洞存在 + 说明影响」，不扩大、不拖库、不留痕。
5. **派活给执行角色，自己做判断与核对**；执行角色一次性交付，不往下派。
6. **技能先加载再动手**，禁止凭记忆猜参数。

## 安装 / 使用

```bash
git clone git@github.com:alj385494-hub/dsh-redteam-skills.git
cd dsh-redteam-skills/dsh-purge-redteam
# 技能：拷进 DSH 技能目录
cp -r skills/*.md ~/.dsh/skills/
# 规范：放到工作区根，AGENTS.md 顶部引 OPERATING-MODEL.md
cp docs/AGENTS.md docs/OPERATING-MODEL.md <workspace>/
# 预设：见 config/presets/ 与 config/cordis.patch.yml（改完完全退出 DSH 重启）
```

## 版本

见 `VERSION`。
