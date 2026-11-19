#!/usr/bin/env bash
# 插件快照工具（2026-11-14）
# 目的：任何对红队插件（lib/ presets/ skills/ cordis.patch.yml）与各靶标 agents/*.md 的改动前，
#       先做一次可回滚的快照，并生成 sha256 清单。
# 用法：
#   bash runs/tools/plugin_snapshot.sh            # 快照到 runs/backup/plugin-<时间戳>/
#   bash runs/tools/plugin_snapshot.sh mynote     # 带自定义标签
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1

TS=$(date +%Y%m%d-%H%M%S)
TAG=${1:-snapshot}
OUT="runs/backup/plugin-${TS}-${TAG}"
PROFILE="$HOME/.dsh/profiles/desktop"
ENG="$HOME/.dsh/redteam/engagements"

mkdir -p "$OUT"

# 1) 插件本体（两份：node_modules 实际加载 + vendor）
for p in "$PROFILE/node_modules/dsh-redteam-mode" "$PROFILE/vendor/dsh-redteam-mode"; do
  [ -d "$p" ] || continue
  name=$(basename "$(dirname "$p")")
  mkdir -p "$OUT/plugin-$name"
  # 只备关键内容：lib/presets/skills/cordis.patch.yml/package.json（不含 node_modules 依赖）
  for sub in lib presets skills cordis.patch.yml package.json README.md; do
    [ -e "$p/$sub" ] && cp -r "$p/$sub" "$OUT/plugin-$name/" 2>/dev/null || true
  done
done

# 2) 各靶标角色提示词
if [ -d "$ENG" ]; then
  mkdir -p "$OUT/engagements"
  for e in "$ENG"/*/; do
    [ -d "$e/agents" ] || continue
    cp -r "$e/agents" "$OUT/engagements/$(basename "$e")-agents"
  done
fi

# 3) 用户级技能（~/.dsh/skills，48 个；改判据时的回滚点）
if [ -d "$HOME/.dsh/skills" ]; then
  mkdir -p "$OUT/user-skills"
  cp -r "$HOME/.dsh/skills/." "$OUT/user-skills/"
fi

# 4) 关键配置
cp "$PROFILE/cordis.patch.yml" "$OUT/profile-cordis.patch.yml" 2>/dev/null || true
cp "$PROFILE/package.json" "$OUT/profile-package.json" 2>/dev/null || true

# 4) sha256 清单
( cd "$OUT" && find . -type f ! -name MANIFEST.sha256 -exec sha256sum {} \; | sort -k2 > MANIFEST.sha256 )

echo "快照 -> $OUT"
echo "文件数: $(wc -l < "$OUT/MANIFEST.sha256")"
echo "回滚示例："
echo "  cp -r $OUT/plugin-node_modules/* $PROFILE/node_modules/dsh-redteam-mode/"
echo "  cp -r $OUT/engagements/某工科高校-agents/* $ENG/某工科高校/agents/"
