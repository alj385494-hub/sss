#!/bin/bash
# DSH 更新后 / 随时自检（薄包装：逻辑都在 dsh_state.py，避免两处判据各自过时）
#
#   bash runs/tools/post-update-check.sh            # 与基线对比，有漂移则非 0 退出
#   bash runs/tools/post-update-check.sh --save     # 确认状态正确后，用它更新基线
#
# 基线文件: runs/tools/dsh-baseline.json
# 背景: 每次 DSH 更新曾导致 profile bundles 被重置、vendor 手工修复被覆盖、
#       社区插件与新版 API 不兼容 —— 这些都在 dsh_state.py 里被显式检查。

cd "$(dirname "$0")/../.." || exit 1
PY="<HOME>/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/python.exe"
export PYTHONIOENCODING=utf-8

"$PY" runs/tools/dsh_state.py "$@"
rc=$?

if [ "$rc" -eq 0 ]; then
  echo
  echo "── 仍需人工确认（脚本看不到的 GUI 状态）──"
  echo "  1. 设置 → 插件：include:agent-team / tool-agent-team / ui-agent-team 均 active 且无 diagnostic"
  echo "  2. 记忆系统 mnemon_status 正常"
  echo "  3. 团队功能：根会话 → 模型与推理菜单 → 「启用智能体团队协作」（rc.3 起默认关闭）"
  echo "  4. 插件市场：设置里是否配了索引源（indexes 默认空 → Discover 页为空属正常）"
else
  echo
  echo "── 有漂移：按上面每条的『修复:』执行 ──"
  echo "  修完若确认状态正确，用 --save 更新基线，避免下次重复报同一项："
  echo "    bash runs/tools/post-update-check.sh --save"
fi
exit "$rc"
