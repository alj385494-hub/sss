# -*- coding: utf-8 -*-
"""A 阶段：搭建三层发布骨架 runs/packs/。"""
import io
import json
import os
import re
import shutil
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

WS = r"<HOME>\Documents\deepseek-harness\default-workspace"
SK = r"<HOME>\.dsh\skills"
VENDOR = r"<HOME>\.dsh\profiles\desktop\vendor\dsh-redteam-mode"
PACKS = os.path.join(WS, "runs", "packs")

MIT = """MIT License

Copyright (c) 2026 <YOUR NAME>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, "w", encoding="utf-8", newline="\n").write(text)


def parse_skill(path):
    t = io.open(path, encoding="utf-8").read()
    name = re.search(r"^name:\s*(.+)$", t, re.M)
    desc = re.search(r"^description:\s*(.+)$", t, re.M)
    cat = re.search(r"^category:\s*(.+)$", t, re.M)
    tags = re.search(r"^tags:\s*(.+)$", t, re.M)
    return {
        "name": (name.group(1).strip() if name else os.path.basename(path)[:-3]),
        "description": (desc.group(1).strip()[:120] if desc else ""),
        "category": (cat.group(1).strip() if cat else ""),
        "tags": (tags.group(1).strip() if tags else ""),
        "lines": t.count("\n") + 1,
    }


# ---------- ① 基座 ----------
base_dst = os.path.join(PACKS, "dsh-redteam-mode")
if os.path.isdir(base_dst):
    shutil.rmtree(base_dst)
shutil.copytree(VENDOR, base_dst,
                ignore=shutil.ignore_patterns("*.bak-*", "node_modules", "*.log"))
print("① 基座已复制: dsh-redteam-mode (%d 文件)" % sum(len(f) for _, _, f in os.walk(base_dst)))

# ---------- ② 能力层 ----------
CAP = os.path.join(PACKS, "dsh-pentest-skills")
os.makedirs(os.path.join(CAP, "skills"), exist_ok=True)
shutil.copy2(os.path.join(SK, "target-type-playbook.md"),
             os.path.join(CAP, "skills", "target-type-playbook.md"))
w(os.path.join(CAP, "LICENSE"), MIT)
w(os.path.join(CAP, "manifest.json"), json.dumps({
    "name": "dsh-pentest-skills",
    "version": "0.1.0",
    "layer": "capability",
    "license": "MIT",
    "description": "平台无关的漏洞挖掘能力技能集：靶标类型打法、通用接口挖掘手法。不含任何漏洞平台规则",
    "install": "把 skills/*.md 复制到 $DSH_HOME/skills/（或通过 dsh 插件安装）",
    "skills": [parse_skill(os.path.join(CAP, "skills", f))
               for f in sorted(os.listdir(os.path.join(CAP, "skills"))) if f.endswith(".md")],
}, ensure_ascii=False, indent=2) + "\n")
w(os.path.join(CAP, "README.md"), """# dsh-pentest-skills

平台无关的漏洞挖掘**能力层**技能集。

## 原则

- **只放能力，不放规则**：不带任何漏洞平台的收录标准、驳回规则、定级口径
- **可单独拼接**：任何 DSH 插件/预设都能叠加本技能集，不会引入平台误判
- **中文正文 + 英文术语**：`name`/`tags` 用英文便于路由，正文中文便于阅读

## 安装

```bash
cp skills/*.md "$DSH_HOME/skills/"
```

或作为 bundle 引用（把 `skills/` 目录加进 `skill-filesystem` 的 `customSkillDirs`）。

## 技能清单

见 `manifest.json`。

## 与其它层的关系

| 层 | 示例包 | 提供什么 |
|---|---|---|
| 基座 | `dsh-redteam-mode` | 工具与预设、41 个能力技能 |
| **能力层（本包）** | `dsh-pentest-skills` | 平台无关的挖掘方法论 |
| 平台层 | `dsh-src-butian-cn` / `dsh-src-edu-cn` | 特定平台的收录/定级/提交规则 |
| 环境层 | `dsh-workspace-env` | 个人工作区约定（台账等） |
""")
print("② 能力层已建: dsh-pentest-skills")

# ---------- ③ 平台层（补天） ----------
BUT = os.path.join(PACKS, "dsh-src-butian-cn")
os.makedirs(os.path.join(BUT, "skills"), exist_ok=True)
for f in ("butian-submit.md", "butian-rejection-cases.md"):
    shutil.copy2(os.path.join(SK, f), os.path.join(BUT, "skills", f))
w(os.path.join(BUT, "LICENSE"), MIT)
w(os.path.join(BUT, "manifest.json"), json.dumps({
    "name": "dsh-src-butian-cn",
    "version": "0.1.0",
    "layer": "platform",
    "platform": "butian (补天)",
    "license": "MIT",
    "description": "补天平台专属规则：表单 13 项类型、4+2 段式报告、驳回案例与规避规则",
    "install": "只有需要向补天提交时才安装",
    "skills": [parse_skill(os.path.join(BUT, "skills", f))
               for f in sorted(os.listdir(os.path.join(BUT, "skills"))) if f.endswith(".md")],
}, ensure_ascii=False, indent=2) + "\n")
w(os.path.join(BUT, "README.md"), """# dsh-src-butian-cn（平台层）

**只装给需要向补天提交的场景。** 不装它，能力层技能完全不受影响。

## 内容

| 技能 | 管什么 |
|---|---|
| `butian-submit` | 表单 13 项漏洞类型、4+2 段式报告、截图规范、简要描述、行业归属 |
| `butian-rejection-cases` | 三问卡 Q1–Q4、R1–R9 规则、真实驳回案例、打分校准 |

## 为什么单独成包

平台规则会随时间变（收录范围、驳回口径）。单独成包后：

- 换平台只需换这一层，能力层不用动
- 别人投 HackerOne / 其它 SRC，可以完全不用本包
- 平台规则更新不影响通用方法论
""")
print("③ 平台层已建: dsh-src-butian-cn")

# ---------- ④ 平台层（EDUSRC） ----------
EDU = os.path.join(PACKS, "dsh-src-edu-cn")
os.makedirs(os.path.join(EDU, "skills"), exist_ok=True)
shutil.copy2(os.path.join(SK, "edu-target-rules.md"),
             os.path.join(EDU, "skills", "edu-target-rules.md"))
w(os.path.join(EDU, "LICENSE"), MIT)
w(os.path.join(EDU, "manifest.json"), json.dumps({
    "name": "dsh-src-edu-cn",
    "version": "0.1.0",
    "layer": "platform",
    "platform": "EDUSRC (教育漏洞报告平台)",
    "license": "MIT",
    "description": "教育行业漏洞评级口径：等级定义、22 项忽略清单、7 项降级、无害化三性",
    "install": "打高校/教育单位时安装；口径同时对其它行业有参考价值",
    "skills": [parse_skill(os.path.join(EDU, "skills", "edu-target-rules.md"))],
}, ensure_ascii=False, indent=2) + "\n")
w(os.path.join(EDU, "README.md"), """# dsh-src-edu-cn（平台层）

教育行业漏洞报告平台（EDUSRC）的官方评级口径。

## 为什么单独

打高校/教育单位时，用它的口径预判"这个洞在教育行业会被怎么判"。
但它**不是补天的规则**，两者定级有差异（见技能第六节）。

## 内容

- 严重/高/中/低 等级定义
- **22 项忽略清单**（含用户名枚举、URL 跳转、CORS、源码/路径/内网 IP 泄露）
- 7 项降级原因
- 无害化验证三性（机密性/可用性/完整性）
""")
print("④ 平台层已建: dsh-src-edu-cn")

# ---------- ⑤ 环境层 ----------
ENV = os.path.join(PACKS, "dsh-workspace-env")
os.makedirs(os.path.join(ENV, "skills"), exist_ok=True)
shutil.copy2(os.path.join(SK, "my-work-ledger.md"),
             os.path.join(ENV, "skills", "my-work-ledger.md"))
w(os.path.join(ENV, "LICENSE"), MIT)
w(os.path.join(ENV, "manifest.json"), json.dumps({
    "name": "dsh-workspace-env",
    "version": "0.1.0",
    "layer": "workspace",
    "license": "MIT",
    "description": "个人工作区约定：靶标台账（桌面 xlsx）状态更新。仅本机适用，发布时建议改成模板",
    "install": "仅个人环境安装；发布给他人时应移除或改写为模板",
    "skills": [parse_skill(os.path.join(ENV, "skills", "my-work-ledger.md"))],
}, ensure_ascii=False, indent=2) + "\n")
w(os.path.join(ENV, "README.md"), """# dsh-workspace-env（环境层）

**个人工作区约定，不建议发布给他人**（内含本机绝对路径与工具名）。

## 用途

- 靶标台账（桌面 `域名信息汇总表.xlsx`）状态列更新
- 被 WPS/Excel 占用时的正确处置（不强杀进程）

## 发布建议

如果要放进公开仓库，把它改写为**模板**（路径换成占位符），或干脆不发布本层。
""")
print("⑤ 环境层已建: dsh-workspace-env")

# ---------- ⑥ 顶层 README ----------
w(os.path.join(PACKS, "README.md"), """# DSH 红队技能分层发布包

把红队作战技能拆成**四层**，按需组合。核心原则：**技能保持纯净**——
能力技能不含任何平台规则，平台规则单独成包，拼接时不会互相干扰。

## 分层

| 层 | 包名 | 内容 | 是否必装 |
|---|---|---|---|
| **基座** | `dsh-redteam-mode` | 预设、工具、控制台、41 个能力技能 | 必装 |
| **能力层** | `dsh-pentest-skills` | 平台无关的挖掘方法论（靶标打法、接口手法） | 建议 |
| **平台层** | `dsh-src-butian-cn` | 补天表单/报告/驳回规则 | 按需（投补天） |
| **平台层** | `dsh-src-edu-cn` | EDUSRC 教育行业评级口径 | 按需（打高校） |
| **环境层** | `dsh-workspace-env` | 个人台账约定（本机） | 仅自己 |

## 组合示例

```
目标：打高校并投补天
装：dsh-redteam-mode + dsh-pentest-skills + dsh-src-butian-cn + dsh-src-edu-cn

目标：打企业 SRC（HackerOne）
装：dsh-redteam-mode + dsh-pentest-skills
（平台层自己写）
```

## 安装

每个包的 `skills/*.md` 复制到 `$DSH_HOME/skills/`，或在其 `cordis.patch.yml` 里把目录加进
`skill-filesystem` 的 `customSkillDirs`（**注意：同一作用域内只挂一次 `skill-filesystem`**，
多挂会报 `service has been registered`）。

## 许可证与署名

| 包 | 许可证 | 来源 |
|---|---|---|
| `dsh-redteam-mode` | **MIT**，© Jueze | https://github.com/Jueze-2019/dsh-redteam-mode （fork，保留原版权声明） |
| 其余各包 | MIT | 本仓库原创；借鉴来源见各包 `NOTICE`（如有） |
""")
print("⑥ 顶层 README 已建")

print("\n=== 骨架结构 ===")
for root, dirs, files in os.walk(PACKS):
    depth = root[len(PACKS):].count(os.sep)
    if depth > 2:
        continue
    print("  " * depth + os.path.basename(root) + "/")
    if depth < 2:
        for f in sorted(files)[:8]:
            print("  " * (depth + 1) + f)
