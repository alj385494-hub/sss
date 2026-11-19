#!/bin/bash
VBOX="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
VM="kali-linux-2026.3-virtualbox-amd64"; U="kali"; P="kali"
TMPDIR_WIN="<HOME>/AppData/Local/Temp"
kali() {
  local script="$1"
  local tag="$$_$RANDOM"
  local local_sh="$TMPDIR_WIN/dsh_k_$tag.sh"
  local guest_sh="/tmp/dsh_k_$tag.sh"
  { echo 'exec < /dev/null'; echo 'export PATH="$HOME/go/bin:$PATH"'; echo "$script"; } > "$local_sh"
  MSYS2_ARG_CONV_EXCL="$guest_sh;/bin/bash" "$VBOX" guestcontrol "$VM" copyto "$local_sh" "$guest_sh" --username "$U" --password "$P" >/dev/null 2>&1
  MSYS2_ARG_CONV_EXCL="$guest_sh;/bin/bash" "$VBOX" guestcontrol "$VM" run --exe "/bin/bash" --username "$U" --password "$P" --wait-stdout -- "$guest_sh" 2>&1
  rm -f "$local_sh"
}
kaliget() { MSYS2_ARG_CONV_EXCL="$1" "$VBOX" guestcontrol "$VM" copyfrom "$1" "$2" --username "$U" --password "$P" >/dev/null 2>&1; }
kaliput() { MSYS2_ARG_CONV_EXCL="$2" "$VBOX" guestcontrol "$VM" copyto "$1" "$2" --username "$U" --password "$P" >/dev/null 2>&1; }
