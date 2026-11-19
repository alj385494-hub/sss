#!/bin/bash
# kali_gui_shot.sh —— 在 Kali（Xvfb :99）里抓"真实软件窗口"截图（含 Burp / 浏览器），并取回宿主机
#
# 来源：session-696837e1（2026-11-14）实证方法，seq 13196 / 13252 / 13358 / 13400
# 用法：
#   bash runs/tools/kali_gui_shot.sh burp-launch                    # 启动 Burp（--use-defaults 自动跳过项目对话框）
#   bash runs/tools/kali_gui_shot.sh burp-repeater 469 351 301 55   # 点 (469,351) 再点 Repeater 标签(301,55)，然后截图
#   bash runs/tools/kali_gui_shot.sh shot  <输出名>                  # 直接抓当前屏幕
#   bash runs/tools/kali_gui_shot.sh click <x> <y> [等待秒]          # 单点点击
#   bash runs/tools/kali_gui_shot.sh key   <键名>                    # 发按键（如 ctrl+t）
# 输出：runs/<SHOT_DIR>/<输出名>.png（默认 runs/tmp/）
set -uo pipefail
VBOX="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
VM="kali-linux-2026.3-virtualbox-amd64"
WSDIR="<HOME>/Documents/deepseek-harness/default-workspace"
OUTDIR="${SHOT_DIR:-$WSDIR/runs/tmp}"
mkdir -p "$OUTDIR"

# 在 Kali 里跑一段脚本（脚本内容用 base64 传，避免引号/编码问题）
krun() {
  local script="$1" tmo="${2:-120}"
  local b64; b64=$(printf '%s' "$script" | base64 -w0)
  MSYS2_ARG_CONV_EXCL="/bin/bash" timeout "$tmo" "$VBOX" guestcontrol "$VM" run \
    --exe "/bin/bash" --username kali --password kali --wait-stdout -- \
    -c "echo '$b64' | base64 -d > /tmp/_kgs.sh && bash /tmp/_kgs.sh" 2>/dev/null
}
# 把 Kali 里的文件 base64 取回
kget() {
  local remote="$1" local_out="$2"
  MSYS2_ARG_CONV_EXCL="/bin/bash" timeout 90 "$VBOX" guestcontrol "$VM" run \
    --exe "/bin/bash" --username kali --password kali --wait-stdout -- \
    -c "base64 -w0 '$remote' 2>/dev/null" 2>/dev/null | base64 -d > "$local_out" 2>/dev/null
}

cmd="${1:-}"; shift || true

case "$cmd" in
  burp-launch)
    krun '#!/bin/bash
D=:99; export DISPLAY=$D
pgrep -f "Xvfb $D" >/dev/null || { Xvfb $D -screen 0 1440x900x24 >/tmp/xvfb.log 2>&1 & sleep 2; }
pgrep -f burpsuite >/dev/null && { echo "已在运行"; exit 0; }
nohup burpsuite --use-defaults >/tmp/burp.log 2>&1 &
echo "已启动 burpsuite --use-defaults"
for i in $(seq 1 20); do sleep 6; WID=$(xdotool search --name "Burp Suite" 2>/dev/null | head -1); [ -n "$WID" ] && { echo "窗口出现(第 $((i*6))s) id=$WID"; break; }; done
sleep 8
WID=$(xdotool search --name "Burp Suite" | head -1)
[ -n "$WID" ] && { xdotool windowsize "$WID" 1440 900; xdotool windowmove "$WID" 0 0; echo "已归位 1440x900"; } || echo "NO_WINDOW"
' 400
    ;;

  click)
    x="${1:?x}"; y="${2:?y}"; w="${3:-2}"
    krun "#!/bin/bash
export DISPLAY=:99; xdotool mousemove $x $y click 1; sleep $w; echo 'clicked $x,$y'" 60
    ;;

  key)
    k="${1:?key}"
    krun "#!/bin/bash
export DISPLAY=:99; xdotool key $k; sleep 2; echo 'key $k'" 60
    ;;

  shot)
    name="${1:?输出名（不含扩展名）}"
    krun "#!/bin/bash
export DISPLAY=:99; import -window root /tmp/_kgs.png && echo shot_ok" 60
    kget "/tmp/_kgs.png" "$OUTDIR/$name.png"
    if [ -s "$OUTDIR/$name.png" ]; then
      echo "OK $OUTDIR/$name.png ($(( $(stat -c%s "$OUTDIR/$name.png")/1024 ))KB)"
    else
      echo "FAIL 未取到截图"; exit 1
    fi
    ;;

  burp-repeater)
    # 用法: burp-repeater <SendToRepeater的x> <y> <Repeater标签的x> <y>
    rx="${1:?}"; ry="${2:?}"; tx="${3:?}"; ty="${4:?}"
    krun "#!/bin/bash
export DISPLAY=:99
xdotool mousemove $rx $ry click 1; sleep 4   # 右键菜单项「Send to Repeater」
xdotool mousemove $tx $ty click 1; sleep 4   # 顶部 Repeater 标签
import -window root /tmp/_kgs.png && echo repeater_ok" 120
    kget "/tmp/_kgs.png" "$OUTDIR/burp-repeater.png"
    echo "OK $OUTDIR/burp-repeater.png ($(( $(stat -c%s "$OUTDIR/burp-repeater.png")/1024 ))KB)"
    ;;

  *)
    sed -n '2,14p' "$0"
    exit 1
    ;;
esac
