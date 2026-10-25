#!/usr/bin/env bash
# Opens the live demo layout:
#   left  : presenter steps (press Enter to advance)
#   right : attacker server (top) and gateway audit log (bottom), live
#   browser: admin approval page
# Run from anywhere:  bash ~/zt-agent-firewall/demo/demo.sh
cd "$(dirname "$0")/.." || exit 1
unset DOCKER_HOST
if ! command -v tmux >/dev/null 2>&1; then
  echo "Installing tmux (needs your sudo password once)..."; sudo apt-get install -y tmux || exit 1
fi
[ -f .env ] || bash scripts/init_env.sh
tmux kill-session -t ztdemo 2>/dev/null
tmux new-session -d -s ztdemo -x "$(tput cols)" -y "$(tput lines)" "bash demo/steps.sh"
tmux split-window -h -p 48 -t ztdemo "python3 demo/watch.py attacker"
tmux split-window -v -p 62 -t ztdemo "python3 demo/watch.py audit"
tmux select-pane -t ztdemo:0.0
tmux set -t ztdemo mouse on >/dev/null
tmux attach -t ztdemo
