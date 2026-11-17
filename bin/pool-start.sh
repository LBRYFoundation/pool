#!/bin/bash
################################################################################
# Start the LBRY pool processes in detached tmux sessions (root's tmux server).
#
# Nothing here restarts a process automatically: if a process exits, its tmux
# session stays open and shows the exit code so you can inspect it.
#
# Usage:  sudo ~/pool-start.sh [component ...]      (default: all)
# Components:
#   all          everything below, in dependency order
#   chain        lbcd + lbcwallet
#   lbcd | lbcwallet | stratum | blocknotify | web | debug
#
# Attach:  sudo tmux attach -t <session>      (detach: Ctrl-b d)
# List:    sudo tmux ls
# Stop:    sudo ~/pool-stop.sh [component ...]
#
# Installed by install.sh; settings come from /etc/lbcpool/.
################################################################################

set -euo pipefail

[[ ${EUID} -eq 0 ]] || exec sudo "$0" "$@"

POOL_ETC=/etc/lbcpool
LBC_HOME=/var/lib/lbc
STRATUM_DIR=/var/stratum
WEB_DIR=/var/web
YIIMP_LOG_DIR=/var/log/yiimp
LBCD_RPC=127.0.0.1:9245
LBCWALLET_RPC=127.0.0.1:9244
LBCD_CONF="${LBC_HOME}/.lbcd/lbcd.conf"
LBCWALLET_CONF="${LBC_HOME}/.lbcwallet/lbcwallet.conf"
LBCWALLET_APPDATA="${LBC_HOME}/.lbcwallet"
LBCD_NOTLS=1
LBCD_CERT=""
STRATUM_PORT=3334

# COIN_ID and discovered paths/ports (written by install.sh)
# shellcheck source=/dev/null
. "${POOL_ETC}/pool.env"

running() { tmux has-session -t "=$1" 2>/dev/null; }

# start <session> <command>: run <command> in a new detached session
start() {
  local name="$1" cmd="$2"
  if running "${name}"; then
    echo "${name}: already running (sudo tmux attach -t ${name})"
    return
  fi
  # keep the session open after the process exits so the reason stays visible
  tmux new-session -d -s "${name}" \
    "${cmd}; rc=\$?; echo; echo \"[${name} exited with code \${rc} at \$(date)]\"; exec bash"
  echo "${name}: started"
}

lbcd_ready() {
  lbcctl -C "${POOL_ETC}/lbcctl.conf" -s "${LBCD_RPC}" getblockcount >/dev/null 2>&1
}

lbcwallet_ready() {
  lbcctl -C "${POOL_ETC}/lbcctl.conf" --notls --wallet -s "${LBCWALLET_RPC}" getinfo >/dev/null 2>&1
}

wait_lbcd() {
  local i
  for i in $(seq 1 120); do
    lbcd_ready && return 0
    [[ ${i} -eq 1 ]] && echo "waiting for lbcd RPC on ${LBCD_RPC} ..."
    sleep 1
  done
  echo "WARNING: lbcd RPC not answering yet (still loading?); check: sudo tmux attach -t lbcd"
  return 1
}

start_lbcd() {
  if lbcd_ready || pgrep -x lbcd >/dev/null; then
    echo "lbcd: already running on host"
    return
  fi
  local owner
  owner="$(stat -c '%U' "${LBCD_CONF}" 2>/dev/null || echo lbc)"
  start lbcd "ulimit -n 65536 && runuser -u ${owner} -- /usr/local/bin/lbcd --configfile=${LBCD_CONF}"
}

start_lbcwallet() {
  wait_lbcd || true
  if lbcwallet_ready || pgrep -x lbcwallet >/dev/null; then
    echo "lbcwallet: already running on host"
    return
  fi
  local owner
  owner="$(stat -c '%U' "${LBCWALLET_APPDATA}" 2>/dev/null || echo lbc)"
  start lbcwallet "runuser -u ${owner} -- /usr/local/bin/lbcwallet --configfile=${LBCWALLET_CONF} --appdata=${LBCWALLET_APPDATA}"
}

start_stratum() {
  start stratum "cd ${STRATUM_DIR}/config && ulimit -n 10240 && ulimit -u 32768 && runuser -u www-data -- ${STRATUM_DIR}/stratum lbry"
}

start_blocknotify() {
  # blocknotify-dcr exits if lbcd is not reachable at startup
  if ! wait_lbcd; then
    echo "blocknotify: not started (lbcd not ready); run: sudo ~/pool-start.sh blocknotify"
    return
  fi
  local tls_flag="-notls"
  if [[ "${LBCD_NOTLS}" == 0 && -n "${LBCD_CERT}" ]]; then
    tls_flag="-cert ${LBCD_CERT}"
  fi
  # credentials are read from the env file inside the session, not passed on the command line
  start blocknotify "set -a && . ${POOL_ETC}/blocknotify.env && set +a && runuser -u lbc -- /usr/local/bin/blocknotify-dcr ${tls_flag} -host ${LBCD_RPC} -stratum 127.0.0.1:${STRATUM_PORT} -coinid ${COIN_ID} -bin /usr/local/bin/blocknotify"
}

start_web() {
  local job
  for job in main loop2 blocks; do
    start "${job}" "cd ${WEB_DIR} && runuser -u www-data -- bash ${WEB_DIR}/${job}.sh"
  done
}

start_debug() {
  start debug "touch ${YIIMP_LOG_DIR}/debug.log && tail -F ${YIIMP_LOG_DIR}/debug.log"
}

[[ $# -gt 0 ]] || set -- all
for component in "$@"; do
  case "${component}" in
    all) start_lbcd; start_lbcwallet; start_stratum; start_blocknotify; start_web; start_debug ;;
    chain) start_lbcd; start_lbcwallet ;;
    lbcd) start_lbcd ;;
    lbcwallet) start_lbcwallet ;;
    stratum) start_stratum ;;
    blocknotify) start_blocknotify ;;
    web) start_web ;;
    debug) start_debug ;;
    *) echo "unknown component '${component}' (all|chain|lbcd|lbcwallet|stratum|blocknotify|web|debug)"; exit 1 ;;
  esac
done

echo
tmux ls 2>/dev/null || true
