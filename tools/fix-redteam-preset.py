# -*- coding: utf-8 -*-
"""
修复 dsh-redteam-mode 0.15.8 在 DSH 0.2.2-rc.1 上的两个问题（幂等，可重复跑）

问题 1：cordis.patch.yml 仍在挂载不存在的插件子路径
        `@deepseek-ai/dsh-tool-subagent-control/list-agents`
        症状：红队模式加载失败 / 任务板报
              agent preset is unavailable: tool-subagent-list-agents (...) never started
        背景：presets/redteam/agent.cordis.yml 早已移除该行（留有 .bak-listagents），
              但 bundle patch（cordis.patch.yml）没同步，而实际生效的是 patch。

问题 2：allowedAgentPresets 缺少 redteam-worker-internal-recon
        背景：该预设已声明（id: redteam-worker-internal-recon），主会话角色表也要求
              internal-recon 角色，但白名单里漏了 → 主会话无法派该角色。

用法：
  python fix-redteam-preset.py           # 修复
  python fix-redteam-preset.py --check   # 只检查，不写盘

注意：修改的是 vendor 插件目录，插件升级后会被覆盖，需重跑本脚本。
"""
import io
import os
import shutil
import sys
import time

HOME = os.path.expanduser("~")
PLUGIN = os.path.join(HOME, ".dsh", "profiles", "desktop", "vendor", "dsh-redteam-mode")

TARGETS = [
    os.path.join(PLUGIN, "cordis.patch.yml"),
    os.path.join(PLUGIN, "presets", "redteam", "agent.cordis.yml"),
    os.path.join(HOME, ".dsh", ".agent-presets", "redteam", "agent.cordis.yml"),
]

BAD_PLUGIN = "dsh-tool-subagent-control/list-agents"
MISSING_PRESET = "redteam-worker-internal-recon"
ANCHOR_PRESET = "redteam-worker-internal"


def _backup(path, tag):
    bak = path + ".bak-%s-%d" % (tag, int(time.time()))
    shutil.copy2(path, bak)
    return os.path.basename(bak)


def fix_bad_plugin_row(path, dry):
    """删除 list-agents 插件行（连同其上方 - id: 行）"""
    if not os.path.exists(path):
        return "skip(文件不存在)"
    s = io.open(path, encoding="utf-8").read()
    if BAD_PLUGIN not in s:
        return "ok"

    lines = s.split("\n")
    out, removed = [], 0
    for ln in lines:
        if BAD_PLUGIN in ln:
            while out and out[-1].strip().startswith("- id: tool-subagent-list-agents"):
                out.pop()
                removed += 1
            if len(out) > 1 and out[-1].strip() == "" and out[-2].strip() == "":
                out.pop()
            removed += 1
            continue
        out.append(ln)

    if not dry:
        _backup(path, "fixlist")
        io.open(path, "w", encoding="utf-8", newline="").write("\n".join(out))
    return "fixed(-%d行)" % removed


def fix_allowed_preset(path, dry):
    """只在 allowedAgentPresets 块内补 redteam-worker-internal-recon"""
    if not os.path.exists(path):
        return "skip(文件不存在)"
    s = io.open(path, encoding="utf-8").read()

    lines = s.split("\n")
    out, added, in_block, block_indent = [], 0, False, None
    already = False

    for ln in lines:
        stripped = ln.strip()
        if stripped == "allowedAgentPresets:":
            in_block = True
            block_indent = len(ln) - len(ln.lstrip())
            out.append(ln)
            continue
        if in_block:
            cur = len(ln) - len(ln.lstrip())
            if stripped.startswith("- ") and cur > block_indent:
                if stripped == "- " + MISSING_PRESET:
                    already = True
                out.append(ln)
                if stripped == "- " + ANCHOR_PRESET and not already:
                    out.append(" " * cur + "- " + MISSING_PRESET)
                    added += 1
                continue
            in_block = False
        out.append(ln)

    if already:
        return "ok"
    if added == 0:
        return "skip(未找到锚点)"
    if not dry:
        _backup(path, "allowed")
        io.open(path, "w", encoding="utf-8", newline="").write("\n".join(out))
    return "fixed(+%d)" % added


def main():
    dry = "--check" in sys.argv
    print("=== dsh-redteam-mode 修复%s ===" % ("（检查模式，不写盘）" if dry else ""))
    if not os.path.isdir(PLUGIN):
        print("插件目录不存在:", PLUGIN)
        return 1

    bad = 0
    for p in TARGETS:
        label = p.replace(PLUGIN, "<plugin>").replace(HOME, "~")
        r1 = fix_bad_plugin_row(p, dry)
        r2 = fix_allowed_preset(p, dry)
        flag = ""
        if r1.startswith("fixed") or r2.startswith("fixed"):
            flag = "  ← 已改"
        if "skip" in r2:
            bad += 1
            flag = "  ← 需人工看"
        print("  %-56s list-agents:%-12s allowed:%-14s%s" % (label, r1, r2, flag))

    print()
    if dry:
        print("检查完成。去掉 --check 才会写盘。")
    else:
        print("修复完成。请【完全退出 DSH（含托盘图标）】后重新启动，红队模式才会重新装载。")
    return 0 if bad == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
