#!/bin/bash
################################################################################
# Gracefully stop LBRY pool processes started by pool-start.sh.
#
# Each process gets Ctrl-C (SIGINT) in its tmux session and time to exit
# cleanly. lbcd and lbcwallet are never force-killed (that risks database
# corruption); if they don't exit within the timeout, you get a warning.
#
# Usage:  sudo ~/pool-stop.sh [component ...]       (default: all)
# Components: all | chain | lbcd | lbcwallet | stratum | blocknotify | web | debug
################################################################################

set -euo pipefail

[[ ${EUID} -eq 0 ]] || exec sudo "$0" "$@"

running() { tmux has-session -t "=$1" 2>/dev/null; }

# The session's shell is the pane process; the pool process runs as its child
# until it exits (then the shell execs an idle bash with no children).
busy() {
  local pane_pid
  pane_pid="$(tmux display-message -p -t "=${1}:" '#{pane_pid}' 2>/dev/null)" || return 1
  [[ -n "${pane_pid}" ]] || return 1
  pgrep -P "${pane_pid}" >/dev/null
}

# stop <session> <timeout seconds> <force: 0|1>
stop() {
  local name="$1" timeout="$2" force="$3" pane_pid
  running "${name}" || return 0
  if busy "${name}"; then
    echo "${name}: stopping (timeout ${timeout}s) ..."
    tmux send-keys -t "=${name}:" C-c
    for _ in $(seq 1 "${timeout}"); do
      busy "${name}" || break
      sleep 1
    done
    if busy "${name}"; then
      if [[ "${force}" == 1 ]]; then
        echo "${name}: still running, sending SIGTERM"
        pane_pid="$(tmux display-message -p -t "=${name}:" '#{pane_pid}')"
        pkill -TERM -P "${pane_pid}" || true
        sleep 2
      else
        echo "WARNING: ${name} is still shutting down; session kept (sudo tmux attach -t ${name})"
        return 1
      fi
    fi
  fi
  tmux kill-session -t "=${name}" 2>/dev/null || true
  echo "${name}: stopped"
}

stop_web() {
  local job
  for job in main loop2 blocks; do
    stop "${job}" 60 1
  done
}

[[ $# -gt 0 ]] || set -- all
rc=0
for component in "$@"; do
  case "${component}" in
    # dependents first, lbcd last
    all)
      stop blocknotify 15 1; stop stratum 30 1; stop_web; stop debug 5 1
      stop lbcwallet 120 0 || rc=1
      stop lbcd 600 0 || rc=1
      ;;
    chain) stop lbcwallet 120 0 || rc=1; stop lbcd 600 0 || rc=1 ;;
    lbcd) stop lbcd 600 0 || rc=1 ;;
    lbcwallet) stop lbcwallet 120 0 || rc=1 ;;
    stratum) stop stratum 30 1 ;;
    blocknotify) stop blocknotify 15 1 ;;
    web) stop_web ;;
    debug) stop debug 5 1 ;;
    *) echo "unknown component '${component}' (all|chain|lbcd|lbcwallet|stratum|blocknotify|web|debug)"; exit 1 ;;
  esac
done
exit "${rc}"
