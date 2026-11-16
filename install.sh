#!/usr/bin/env bash
################################################################################
# Original Author: Oakey22
# Maintained by: Coolguy3289
# Version 2.0 (November 2026)
#
# Program:
#   Install the LBRY (LBC) mining pool on Ubuntu 22.04 / 24.04:
#   Nginx, MariaDB, PHP 8.x (Yii 1.1.32), lbcd + lbcwallet, the LBC-only
#   stratum server and the lbcd WebSocket block notifier (blocknotify-dcr).
#
# Usage:
#   Run from a checkout of this repository as a regular user with sudo rights:
#     ./install.sh
#   (If run outside a checkout, POOL_REPO / POOL_BRANCH are cloned instead.)
#
# Optional environment overrides:
#   PHP_VERSION=8.4           install this PHP version from ppa:ondrej/php
#                             (default: the distribution's PHP 8.x package)
#   LBCD_VERSION=v0.22.119    pin the lbcd release      (default: latest release)
#   LBCWALLET_VERSION=...     pin the lbcwallet release (default: latest release)
#   GO_VERSION=go1.27.4       pin the Go toolchain      (default: latest stable)
#   POOL_REPO=<git url>       repository to clone when not run from a checkout
#   POOL_BRANCH=<branch>      branch to clone           (default: repo default)
#
# Re-running is supported: answers are kept in install.conf and generated
# secrets in ~/.lbcpool-secrets, so existing passwords are reused.
################################################################################

set -Eeuo pipefail

output() {
  printf "\E[0;33;40m"
  echo "$1"
  printf "\E[0m"
}

displayErr() {
  echo
  echo "$1"
  echo
  exit 1
}

trap 'displayErr "Installer failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

# "y"/"yes" (case-insensitive)
is_yes() { [[ "${1,,}" =~ ^(y|yes)$ ]]; }
# empty answer counts as yes
is_yes_default() { [[ -z "$1" ]] || is_yes "$1"; }

################################################################################
# Constants
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_NAME="yiimpfrontend"
LBC_HOME="/var/lib/lbc"
LBCD_DIR="${LBC_HOME}/.lbcd"
LBCWALLET_DIR="${LBC_HOME}/.lbcwallet"
LBCD_RPC="127.0.0.1:9245"
LBCWALLET_RPC="127.0.0.1:9244"
LBC_P2P_PORT=9246
STRATUM_PORT=3334
STRATUM_DIR="/var/stratum"
WEB_DIR="/var/web"
YIIMP_LOG_DIR="/var/log/yiimp"
BACKUP_DIR="/var/backups/yiimp"
POOL_ETC="/etc/lbcpool"
SQL_DUMP="2016-04-03-yaamp.sql.gz"
SECRETS_FILE="${HOME}/.lbcpool-secrets"
CREDENTIALS_FILE="${HOME}/pool-credentials.txt"
SEED_FILE="${HOME}/lbcwallet-seed.txt"

################################################################################
# Main routine
################################################################################

# Capture all output in a log file
LOG_FILE="${SCRIPT_DIR}/install.log"
{
  echo "-----------------------------------------------------------------------"
  echo "LBRY Pool install log of" "$(date)"
  echo "Use less -R to view without control characters."
  echo "-----------------------------------------------------------------------"
  echo
} >"${LOG_FILE}"
exec &> >(tee -a "${LOG_FILE}")

# Phase 0: Pre-flight checks and configuration #################################
clear
output "LBRY Pool Installer"
output ""

[[ ${EUID} -eq 0 ]] && displayErr "Run this script as a regular user with sudo rights, not as root."
sudo -v || displayErr "This user needs sudo rights."

# shellcheck source=/dev/null
. /etc/os-release
case "${VERSION_ID:-}" in
  22.04 | 24.04) ;;
  *)
    output "WARNING: this installer targets Ubuntu 22.04/24.04, found ${PRETTY_NAME:-unknown}."
    read -r -p "Continue anyway? [y/N] : " ANSWER
    is_yes "${ANSWER}" || exit 1
    ;;
esac

ARCH="$(dpkg --print-architecture)"
case "${ARCH}" in
  amd64 | arm64) ;;
  *) displayErr "Unsupported architecture ${ARCH}: lbcd/lbcwallet releases exist for amd64 and arm64 only." ;;
esac

output "Make sure you double check before hitting enter!"
output ""

# Load file with last configuration data if available
CONF_FILE="${SCRIPT_DIR}/install.conf"
declare -A CONFMAP=()
if [[ -f "${CONF_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${CONF_FILE}"
fi
# Ask user to enter/change configuration data
read -e -r -p "Enter time zone (e.g. America/New_York): " -i "${CONFMAP['TIME_ZONE']:-UTC}" CONFMAP['TIME_ZONE']
read -e -r -p "Server name (no http:// or www. just example.com): " -i "${CONFMAP['SERVER_NAME']:-}" CONFMAP['SERVER_NAME']
read -e -r -p "Are you using a subdomain (e.g. pool.example.com?) [y/N] : " -i "${CONFMAP['SUB_DOMAIN']:-}" CONFMAP['SUB_DOMAIN']
read -e -r -p "Enter support email (e.g. admin@example.com) : " -i "${CONFMAP['EMAIL']:-}" CONFMAP['EMAIL']
read -e -r -p "Send a test email to the support address? [Y/n] : " -i "${CONFMAP['SEND_EMAIL']:-}" CONFMAP['SEND_EMAIL']
read -e -r -p "Custom admin panel path, replaces /site/adminRights (letters/digits only, e.g. myAdminpanel) : " -i "${CONFMAP['ADMIN_PANEL']:-}" CONFMAP['ADMIN_PANEL']
read -e -r -p "Enter your Public IP for admin access (http://www.whatsmyip.org/) : " -i "${CONFMAP['PUBLIC_IP']:-}" CONFMAP['PUBLIC_IP']
read -e -r -p "Coinbase signature added to found blocks (max 40 chars) : " -i "${CONFMAP['COINBASE_SIG']:-/lbrypool.net/}" CONFMAP['COINBASE_SIG']
read -e -r -p "Install Fail2ban? [Y/n] : " -i "${CONFMAP['INSTALL_FAIL2BAN']:-}" CONFMAP['INSTALL_FAIL2BAN']
read -e -r -p "Install UFW and configure ports? [Y/n] : " -i "${CONFMAP['UFW']:-}" CONFMAP['UFW']
read -e -r -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " -i "${CONFMAP['SSL_INSTALL']:-}" CONFMAP['SSL_INSTALL']

# Validate input that ends up in config files, SQL or sed expressions
[[ -f "/usr/share/zoneinfo/${CONFMAP['TIME_ZONE']}" ]] || displayErr "Unknown time zone '${CONFMAP['TIME_ZONE']}'."
[[ "${CONFMAP['SERVER_NAME']}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || displayErr "Invalid server name '${CONFMAP['SERVER_NAME']}'."
[[ "${CONFMAP['ADMIN_PANEL']}" =~ ^[A-Za-z0-9]+$ ]] || displayErr "Admin panel path must contain letters and digits only."
[[ -z "${CONFMAP['EMAIL']}" || "${CONFMAP['EMAIL']}" =~ ^[^[:space:]\'\"@]+@[^[:space:]\'\"@]+$ ]] || displayErr "Invalid email address."
[[ -z "${CONFMAP['PUBLIC_IP']}" || "${CONFMAP['PUBLIC_IP']}" =~ ^[0-9A-Fa-f.:/,]+$ ]] || displayErr "Invalid admin IP list."
# The coinbase scriptSig must stay <= 100 bytes; stratum caps the signature at 40 bytes
[[ "${CONFMAP['COINBASE_SIG']}" =~ ^[A-Za-z0-9._/:-]{1,40}$ ]] || displayErr "Coinbase signature must be 1-40 chars of A-Z a-z 0-9 . _ / : -"

# Save configuration data to file
declare -p CONFMAP >"${CONF_FILE}"
chmod 600 "${CONF_FILE}"

SERVER_NAME="${CONFMAP['SERVER_NAME']}"
SERVER_NAMES="${SERVER_NAME}"
is_yes "${CONFMAP['SUB_DOMAIN']}" || SERVER_NAMES+=" www.${SERVER_NAME}"

# Generated secrets are kept so re-running the installer does not break a running pool
declare -A SECRETS=()
if [[ -f "${SECRETS_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${SECRETS_FILE}"
fi

# Phase 1: Install dependencies ################################################
clear
output "LBRY Pool Installer"
output ""
output "Updating system and installing required packages."
output ""

export DEBIAN_FRONTEND="noninteractive"

# 1.a: Update packages and upgrade Ubuntu
output "... updating system through apt"
sudo -E apt-get update
sudo -E apt-get -y upgrade
sudo -E apt-get -y autoremove

# 1.b: Install all dependencies
output "Installing required software."
output ""
sudo -E apt-get install -y ca-certificates curl wget jq git rsync unzip xz-utils pwgen tmux gnupg \
  software-properties-common build-essential pkg-config \
  libcurl4-openssl-dev libssl-dev libgmp-dev libmariadb-dev libmariadb-dev-compat \
  mariadb-server mariadb-client nginx memcached sendmail

# PHP: distribution PHP 8.x by default, or a specific version from ppa:ondrej/php
# opcache comes in as a dependency of the CLI package
PHP_EXTENSIONS=(fpm cli common mysql curl gd intl mbstring xml zip bcmath memcache memcached imagick)
if [[ -n "${PHP_VERSION:-}" ]]; then
  output "Installing PHP ${PHP_VERSION} from ppa:ondrej/php"
  sudo -E add-apt-repository -y ppa:ondrej/php
  sudo -E apt-get update
  sudo -E apt-get install -y "${PHP_EXTENSIONS[@]/#/php${PHP_VERSION}-}"
else
  output "Installing the distribution PHP 8.x packages"
  sudo -E apt-get install -y "${PHP_EXTENSIONS[@]/#/php-}"
fi
PHP_VER="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
[[ "${PHP_VER%%.*}" -ge 8 ]] || displayErr "PHP 8.x is required, found PHP ${PHP_VER}."
PHP_FPM_SOCK="/run/php/php${PHP_VER}-fpm.sock"
output "Using PHP ${PHP_VER}"
sudo systemctl enable --now "php${PHP_VER}-fpm"

# 1.c: Time zone and time sync
output "Setting time zone to ${CONFMAP['TIME_ZONE']}"
sudo timedatectl set-timezone "${CONFMAP['TIME_ZONE']}"
sudo timedatectl set-ntp true || output "WARNING: could not enable NTP time sync"

# 1.d: Go toolchain (needed to build blocknotify-dcr against lbcd's rpcclient)
install_go() {
  local json version file sha tmp current=""
  json="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all')"
  version="${GO_VERSION:-$(jq -r '[.[] | select(.stable)][0].version' <<<"${json}")}"
  if [[ -x /usr/local/go/bin/go ]]; then
    current="$(/usr/local/go/bin/go env GOVERSION)"
  fi
  if [[ "${current}" == "${version}" ]]; then
    output "Go ${version} already installed"
    return
  fi
  file="${version}.linux-${ARCH}.tar.gz"
  sha="$(jq -r --arg f "${file}" '[.[].files[] | select(.filename == $f)][0].sha256' <<<"${json}")"
  [[ -n "${sha}" && "${sha}" != "null" ]] || displayErr "Go release ${file} not found on go.dev"
  output "Installing Go ${version}"
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/${file}" "https://go.dev/dl/${file}"
  echo "${sha}  ${tmp}/${file}" | sha256sum -c - || displayErr "Go download checksum mismatch"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "${tmp}/${file}"
  rm -rf "${tmp}"
  echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
}
install_go
export PATH="/usr/local/go/bin:${PATH}"

# 1.e: Optional installs
output "Some optional installs"
if is_yes_default "${CONFMAP['INSTALL_FAIL2BAN']}"; then
  sudo -E apt-get install -y fail2ban
fi
if is_yes_default "${CONFMAP['UFW']}"; then
  sudo -E apt-get install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow ssh
  sudo ufw allow http
  sudo ufw allow https
  sudo ufw allow "${STRATUM_PORT}/tcp"
  sudo ufw allow "${LBC_P2P_PORT}/tcp" # lbcd peer-to-peer
  sudo ufw --force enable
fi

# 1.f: Check email
if [[ -n "${CONFMAP['EMAIL']}" ]]; then
  echo "${CONFMAP['EMAIL']}" >~/.email
  echo "${CONFMAP['EMAIL']}" >~/.forward
  if is_yes_default "${CONFMAP['SEND_EMAIL']}"; then
    output "Testing to see if server emails are sent."
    printf 'Subject: SMTP Test Mail\n\nThis is a mail test for the SMTP Service.\nYou should receive this !\n\nCheers\n' |
      sudo sendmail "${CONFMAP['EMAIL']}" || output "WARNING: test email could not be sent"
  fi
fi

# Phase 2: Secrets #############################################################
gen_secret() { pwgen -s 32 1; }
for key in LBC_RPCUSER LBC_RPCPASS LBC_WALLET_PASS STRATUM_PASSWORD MYSQL_PANELPASSWD MYSQL_STRATUMPASSWD; do
  [[ -n "${SECRETS[${key}]:-}" ]] || SECRETS[${key}]="$(gen_secret)"
done
(umask 077 && declare -p SECRETS >"${SECRETS_FILE}")

# Phase 3: Pool sources and build ##############################################
clear
output "Building the LBRY pool (stratum, blocknotify, blocknotify-dcr)"
output ""

if [[ -f "${SCRIPT_DIR}/stratum/Makefile" && -d "${SCRIPT_DIR}/web" ]]; then
  POOL_SRC="${SCRIPT_DIR}"
  output "Using pool sources from ${POOL_SRC} ($(git -C "${POOL_SRC}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown))"
else
  POOL_SRC="${HOME}/lbcpool-src"
  rm -rf "${POOL_SRC}"
  git clone ${POOL_BRANCH:+--branch "${POOL_BRANCH}"} "${POOL_REPO:-https://github.com/LBRYFoundation/pool.git}" "${POOL_SRC}"
fi

# 3.a: stratum (builds iniparser, algos and sha3 too); direct LBC mining only
make -C "${POOL_SRC}/stratum" clean
make -C "${POOL_SRC}/stratum" -j"$(nproc)"

# 3.b: blocknotify (password comes from STRATUM_PASSWORD at runtime, no source patching)
make -C "${POOL_SRC}/blocknotify"

# 3.c: blocknotify-dcr: lbcd WebSocket block notifier
make -C "${POOL_SRC}/blocknotify-dcr"

# 3.d: install binaries
sudo install -d -m 0755 "${STRATUM_DIR}" "${STRATUM_DIR}/config"
sudo install -m 0755 "${POOL_SRC}/stratum/stratum" "${STRATUM_DIR}/stratum"
sudo install -m 0755 "${POOL_SRC}/blocknotify/blocknotify" /usr/local/bin/blocknotify
sudo install -m 0755 "${POOL_SRC}/blocknotify-dcr/blocknotify-dcr" /usr/local/bin/blocknotify-dcr
sudo install -m 0755 "${POOL_SRC}/bin/yiimp" /usr/local/bin/yiimp
sudo sed -i "s|^ROOTDIR=.*|ROOTDIR=/var/yiimp|" /usr/local/bin/yiimp

# Phase 4: lbcd + lbcwallet ####################################################
clear
output "Installing lbcd and lbcwallet"
output ""

# Download a lbryio GitHub release for this architecture, verify checksums.txt,
# and install the listed binaries into /usr/local/bin.
install_lbry_release() {
  local repo="$1" name="$2" version="$3" json tag asset url sums tmp bin
  shift 3
  if [[ -z "${version}" || "${version}" == "latest" ]]; then
    json="$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${repo}/releases/latest")"
  else
    json="$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${repo}/releases/tags/${version}")"
  fi
  tag="$(jq -r '.tag_name' <<<"${json}")"
  asset="${name}_${tag#v}_linux_${ARCH}.tar.gz"
  url="$(jq -r --arg a "${asset}" '.assets[] | select(.name == $a) | .browser_download_url' <<<"${json}")"
  sums="$(jq -r '.assets[] | select(.name == "checksums.txt") | .browser_download_url' <<<"${json}")"
  [[ -n "${url}" ]] || displayErr "${asset} not found in ${repo} release ${tag}"
  output "... ${name} ${tag}"
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/${asset}" "${url}"
  if [[ -n "${sums}" ]]; then
    curl -fsSL -o "${tmp}/checksums.txt" "${sums}"
    (cd "${tmp}" && grep " ${asset}\$" checksums.txt | sha256sum -c -) || displayErr "${asset} checksum mismatch"
  else
    output "WARNING: ${repo} ${tag} has no checksums.txt, skipping verification"
  fi
  tar -xzf "${tmp}/${asset}" -C "${tmp}"
  for bin in "$@"; do
    sudo install -m 0755 "${tmp}/${bin}" "/usr/local/bin/${bin}"
  done
  rm -rf "${tmp}"
  INSTALLED_VERSIONS+=("${name} ${tag}")
}
INSTALLED_VERSIONS=()
# Pool processes run in tmux sessions (pool-start.sh), never as systemd services.
# Remove units left behind by an earlier installer version, stopping them gracefully.
for unit in lbc-blocknotify lbc-stratum yiimp-main yiimp-loop2 yiimp-blocks lbcwallet lbcd; do
  if [[ -f "/etc/systemd/system/${unit}.service" ]]; then
    output "Removing legacy systemd unit ${unit}.service"
    sudo systemctl disable --now "${unit}.service" || true
    sudo rm -f "/etc/systemd/system/${unit}.service"
  fi
done
sudo systemctl daemon-reload
# Stop running pool processes before replacing their binaries (re-run/upgrade)
if [[ -x "${HOME}/pool-stop.sh" ]] && sudo tmux ls &>/dev/null; then
  sudo "${HOME}/pool-stop.sh" all || displayErr "Pool processes did not stop cleanly; check 'sudo tmux ls' and re-run."
fi
install_lbry_release lbryio/lbcd lbcd "${LBCD_VERSION:-latest}" lbcd lbcctl
install_lbry_release lbryio/lbcwallet lbcwallet "${LBCWALLET_VERSION:-latest}" lbcwallet

# Dedicated service user
if ! id lbc &>/dev/null; then
  sudo useradd --system --home-dir "${LBC_HOME}" --create-home --shell /usr/sbin/nologin lbc
fi
sudo install -d -o lbc -g lbc -m 0750 "${LBC_HOME}" "${LBCD_DIR}" "${LBCWALLET_DIR}"

# lbcd: RPC on localhost only, without TLS (lbcd only allows --notls on localhost)
sudo tee "${LBCD_DIR}/lbcd.conf" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
rpclisten=${LBCD_RPC}
notls=1
txindex=1
EOF

# lbcwallet: uses the same credentials for its own RPC server and for lbcd;
# stratum and the web backend talk to lbcwallet, which proxies chain RPCs to lbcd.
sudo tee "${LBCWALLET_DIR}/lbcwallet.conf" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
rpcconnect=${LBCD_RPC}
noclienttls=1
rpclisten=${LBCWALLET_RPC}
noservertls=1
passphrase=${SECRETS[LBC_WALLET_PASS]}
EOF
sudo chown lbc:lbc "${LBCD_DIR}/lbcd.conf" "${LBCWALLET_DIR}/lbcwallet.conf"
sudo chmod 0600 "${LBCD_DIR}/lbcd.conf" "${LBCWALLET_DIR}/lbcwallet.conf"

# Create the pool wallet once; the seed is written to SEED_FILE for the operator to back up
wallet_exists() { [[ -n "$(sudo find "${LBCWALLET_DIR}" -name wallet.db -print -quit 2>/dev/null)" ]]; }
if ! wallet_exists; then
  output "Creating the pool wallet"
  CREATE_OUT="$(mktemp)"
  # shellcheck disable=SC2024 # output file is intentionally owned by the installing user
  (printf 'no\n' | sudo -u lbc /usr/local/bin/lbcwallet -C "${LBCWALLET_DIR}/lbcwallet.conf" \
    -A "${LBCWALLET_DIR}" --create >"${CREATE_OUT}" 2>&1) &
  CREATE_PID=$!
  for _ in $(seq 1 90); do
    wallet_exists && break
    kill -0 "${CREATE_PID}" 2>/dev/null || break
    sleep 1
  done
  sleep 3
  sudo pkill -u lbc -f 'lbcwallet.*--create' 2>/dev/null || true
  wait "${CREATE_PID}" 2>/dev/null || true
  if wallet_exists; then
    (umask 077 && {
      echo "lbcwallet seed for the LBRY pool wallet, created $(date)"
      echo "Store it offline and delete this file."
      echo "Wallet passphrase is in ${SECRETS_FILE} (LBC_WALLET_PASS)."
      echo
      grep -i "seed" "${CREATE_OUT}" || cat "${CREATE_OUT}"
    } >"${SEED_FILE}")
  else
    output "WARNING: wallet creation did not finish. Output:"
    cat "${CREATE_OUT}"
    output "Create it manually: sudo -u lbc lbcwallet -C ${LBCWALLET_DIR}/lbcwallet.conf -A ${LBCWALLET_DIR} --create"
  fi
  rm -f "${CREATE_OUT}"
fi

# lbcctl convenience config for the operator: `lbcctl getblockchaininfo`, `lbcctl --wallet getbalance`
install -d -m 0700 "${HOME}/.lbcctl"
(umask 077 && cat >"${HOME}/.lbcctl/lbcctl.conf" <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
notls=1
EOF
)
lbcctl_wallet() { lbcctl -C "${HOME}/.lbcctl/lbcctl.conf" --wallet -s "${LBCWALLET_RPC}" "$@"; }

# Phase 5: Database ############################################################
clear
output "Now for the database fun!"
output ""
sudo systemctl enable --now mariadb

# MariaDB root uses unix_socket auth on Ubuntu, so `sudo mysql` needs no password.
# Pool users only get privileges on the pool database.
sudo mysql <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER IF NOT EXISTS 'panel'@'localhost' IDENTIFIED BY '${SECRETS[MYSQL_PANELPASSWD]}';
ALTER USER 'panel'@'localhost' IDENTIFIED BY '${SECRETS[MYSQL_PANELPASSWD]}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO 'panel'@'localhost';
CREATE USER IF NOT EXISTS 'stratum'@'localhost' IDENTIFIED BY '${SECRETS[MYSQL_STRATUMPASSWD]}';
ALTER USER 'stratum'@'localhost' IDENTIFIED BY '${SECRETS[MYSQL_STRATUMPASSWD]}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO 'stratum'@'localhost';
FLUSH PRIVILEGES;
EOF

# Client config: `mysql --defaults-group-suffix=host1` (panel) / host2 (stratum)
(umask 077 && cat >"${HOME}/.my.cnf" <<EOF
[clienthost1]
user=panel
password=${SECRETS[MYSQL_PANELPASSWD]}
database=${DB_NAME}
host=localhost
[clienthost2]
user=stratum
password=${SECRETS[MYSQL_STRATUMPASSWD]}
database=${DB_NAME}
host=localhost
EOF
)

# Import with a relaxed sql_mode: the 2016 dump predates MariaDB strict mode.
# The runtime keeps strict mode, so oversized values fail instead of being truncated.
import_sql() {
  { echo "SET SESSION sql_mode='NO_ENGINE_SUBSTITUTION';"; cat; } | mysql --defaults-group-suffix=host1 --force
}

TABLE_COUNT="$(sudo mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'")"
if [[ "${TABLE_COUNT}" -eq 0 ]]; then
  output "Performing the SQL import"
  zcat "${POOL_SRC}/sql/${SQL_DUMP}" | import_sql
  # every migration newer than the dump, in date order (includes the LBC stratum migrations)
  for f in "${POOL_SRC}"/sql/*.sql; do
    [[ "$(basename "${f}")" > "${SQL_DUMP%%-yaamp*}-z" ]] || continue
    output "... $(basename "${f}")"
    import_sql <"${f}" || output "WARNING: $(basename "${f}") reported errors (see above)"
  done
else
  output "Database ${DB_NAME} already has tables, applying only the idempotent LBC migrations"
  for f in "${POOL_SRC}"/sql/2026-*.sql; do
    output "... $(basename "${f}")"
    import_sql <"${f}"
  done
fi

# Phase 6: Pool processes ######################################################
clear
output "Configuring pool processes"
output ""

sudo install -d -m 0750 -o root -g lbc "${POOL_ETC}"
# Sourced by pool-start.sh for blocknotify-dcr; STRATUM_PASSWORD is inherited by the blocknotify child process
sudo tee "${POOL_ETC}/blocknotify.env" >/dev/null <<EOF
LBCD_RPCUSER=${SECRETS[LBC_RPCUSER]}
LBCD_RPCPASS=${SECRETS[LBC_RPCPASS]}
STRATUM_PASSWORD=${SECRETS[STRATUM_PASSWORD]}
EOF
# lbcctl config used by pool-start.sh to wait for lbcd's RPC
sudo tee "${POOL_ETC}/lbcctl.conf" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
notls=1
EOF
# Non-secret settings for pool-start.sh (COIN_ID is filled in once the coin record exists)
if [[ ! -f "${POOL_ETC}/pool.env" ]]; then
  echo "COIN_ID=" | sudo tee "${POOL_ETC}/pool.env" >/dev/null
fi
sudo chown root:lbc "${POOL_ETC}/blocknotify.env" "${POOL_ETC}/lbcctl.conf" "${POOL_ETC}/pool.env"
sudo chmod 0640 "${POOL_ETC}/blocknotify.env" "${POOL_ETC}/lbcctl.conf" "${POOL_ETC}/pool.env"

# Start/stop helpers: every process runs in its own tmux session (root's tmux
# server) and is never restarted automatically.
install -m 0755 "${POOL_SRC}/bin/pool-start.sh" "${HOME}/pool-start.sh"
install -m 0755 "${POOL_SRC}/bin/pool-stop.sh" "${HOME}/pool-stop.sh"

# lbcd + lbcwallet are needed now to get the pool wallet address
sudo "${HOME}/pool-start.sh" chain

# Pool wallet address (Base58 legacy; stratum needs a b.../r... address when
# lbcwallet does not return witness_version/witness_program in validateaddress)
MASTER_WALLET="$(sudo mysql -N -e "SELECT IFNULL(master_wallet,'') FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1" || true)"
if [[ -z "${MASTER_WALLET}" ]]; then
  output "Requesting a pool wallet address from lbcwallet"
  for _ in $(seq 1 30); do
    MASTER_WALLET="$(lbcctl_wallet getnewaddress default legacy 2>/dev/null || true)"
    [[ "${MASTER_WALLET}" =~ ^[br][1-9A-HJ-NP-Za-km-z]{25,40}$ ]] && break
    MASTER_WALLET=""
    sleep 2
  done
  [[ -n "${MASTER_WALLET}" ]] || output "WARNING: could not get a wallet address; set coins.master_wallet for LBC in the admin panel"
fi

# LBC coin row: stratum/web talk to lbcwallet, which proxies chain RPCs to lbcd
sudo mysql "${DB_NAME}" <<EOF
INSERT INTO coins (name, symbol, algo, image, enable, auto_ready, visible, installed,
  rpchost, rpcport, rpcuser, rpcpasswd, rpcencoding, rpccurl, rpcssl, account,
  hassubmitblock, hasgetinfo, usesegwit, txmessage, mature_blocks, block_time,
  conf_folder, program, link_site, link_github)
SELECT 'LBRY Credits', 'LBC', 'lbry', '/images/coin-LBRY.png', 1, 1, 1, 1,
  '127.0.0.1', ${LBCWALLET_RPC##*:}, '${SECRETS[LBC_RPCUSER]}', '${SECRETS[LBC_RPCPASS]}', 'LBC', 0, 0, 'default',
  1, 1, 1, 0, 100, 150,
  '${LBCWALLET_DIR}', 'lbcwallet', 'https://lbry.com', 'https://github.com/lbryio/lbcd'
FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM coins WHERE symbol='LBC');
UPDATE coins SET algo='lbry', rpchost='127.0.0.1', rpcport=${LBCWALLET_RPC##*:},
  rpcuser='${SECRETS[LBC_RPCUSER]}', rpcpasswd='${SECRETS[LBC_RPCPASS]}',
  rpcencoding='LBC', rpccurl=0, rpcssl=0, installed=1
  WHERE symbol='LBC';
UPDATE coins SET master_wallet='${MASTER_WALLET}' WHERE symbol='LBC' AND '${MASTER_WALLET}' <> '';
EOF
COIN_ID="$(sudo mysql -N -e "SELECT id FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1")"
[[ -n "${COIN_ID}" ]] || displayErr "Could not create the LBC coin record."
echo "COIN_ID=${COIN_ID}" | sudo tee "${POOL_ETC}/pool.env" >/dev/null

# Stratum config (written in full; the old sed edits did not match config.sample)
sudo tee "${STRATUM_DIR}/config/lbry.conf" >/dev/null <<EOF
[TCP]
server = ${SERVER_NAME}
port = ${STRATUM_PORT}
password = ${SECRETS[STRATUM_PASSWORD]}

[SQL]
host = localhost
database = ${DB_NAME}
username = stratum
password = ${SECRETS[MYSQL_STRATUMPASSWD]}
port = 3306

[STRATUM]
algo = lbry
difficulty = 128
max_ttf = 40000000
coinbase_sig = ${CONFMAP['COINBASE_SIG']}
EOF
sudo chmod 0640 "${STRATUM_DIR}/config/lbry.conf"
sudo chown -R www-data:www-data "${STRATUM_DIR}"

# Phase 7: Web #################################################################
clear
output "Making Web Server Magic Happen!"
output ""

sudo install -d -m 0755 "${WEB_DIR}"
sudo rsync -a --delete \
  --exclude 'serverconfig.php' --exclude 'yaamp/runtime/***' --exclude 'assets/***' \
  "${POOL_SRC}/web/" "${WEB_DIR}/"
sudo install -d "${WEB_DIR}/yaamp/runtime" "${WEB_DIR}/assets"
# custom admin entrance (applied to the deployed copy, not the git checkout)
sudo sed -i "s/AdminRights/${CONFMAP['ADMIN_PANEL']}/" "${WEB_DIR}/yaamp/modules/site/SiteController.php"
# `yiimp` console helper expects ROOTDIR/web
sudo install -d /var/yiimp
sudo ln -sfn "${WEB_DIR}" /var/yiimp/web

sudo install -d -o www-data -g www-data -m 0750 "${YIIMP_LOG_DIR}" "${BACKUP_DIR}"

# Only pool settings here; everything else falls back to yaamp/defaultconfig.php
sudo tee "${WEB_DIR}/serverconfig.php" >/dev/null <<EOF
<?php
// Generated by install.sh on $(date -u +%Y-%m-%d). Defaults: yaamp/defaultconfig.php

ini_set('date.timezone', 'UTC');

define('YAAMP_LOGS', '${YIIMP_LOG_DIR}');
define('YAAMP_HTDOCS', '${WEB_DIR}');
define('YAAMP_BIN', '/var/bin');

define('YAAMP_DBHOST', 'localhost');
define('YAAMP_DBNAME', '${DB_NAME}');
define('YAAMP_DBUSER', 'panel');
define('YAAMP_DBPASSWORD', '${SECRETS[MYSQL_PANELPASSWD]}');
define('YIIMP_MYSQLDUMP_PATH', '${BACKUP_DIR}');

define('YAAMP_PRODUCTION', true);
define('YAAMP_RENTAL', false);
define('YAAMP_ALLOW_EXCHANGE', false);
define('YAAMP_USE_NICEHASH_API', false);
define('YAAMP_LIMIT_ESTIMATE', false);

define('YAAMP_FEES_MINING', 0.5);
define('YAAMP_PAYMENTS_FREQ', 3*60*60);
define('YAAMP_PAYMENTS_MINI', 0.001);

define('YIIMP_PUBLIC_EXPLORER', true);
define('YIIMP_PUBLIC_BENCHMARK', false);
define('YIIMP_FIAT_ALTERNATIVE', 'USD');

define('YAAMP_SITE_URL', '${SERVER_NAME}');
define('YAAMP_STRATUM_URL', YAAMP_SITE_URL); // change if your stratum server is on a different host
define('YAAMP_SITE_NAME', 'LBRY Pool');
define('YAAMP_ADMIN_EMAIL', '${CONFMAP['EMAIL']}');
define('YAAMP_ADMIN_IP', '${CONFMAP['PUBLIC_IP']}'); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
define('YAAMP_ADMIN_WEBCONSOLE', true);
define('YAAMP_NOTIFY_NEW_COINS', false);
define('YAAMP_CREATE_NEW_COINS', false);
define('YAAMP_DEFAULT_ALGO', 'lbry');
define('YAAMP_USE_NGINX', true);

\$cold_wallet_table = array();
\$configFixedPoolFees = array();
\$configCustomPorts = array();
\$configAlgoNormCoef = array();
EOF

# mysqldump credentials for the web backup job
sudo install -d -m 0755 /etc/yiimp
sudo tee /etc/yiimp/keys.php >/dev/null <<EOF
<?php
/* Generated by install.sh, read by the web backend (backups) */
define('YIIMP_MYSQLDUMP_USER', 'panel');
define('YIIMP_MYSQLDUMP_PASS', '${SECRETS[MYSQL_PANELPASSWD]}');
EOF

sudo chown -R www-data:www-data "${WEB_DIR}"
sudo chmod 0640 "${WEB_DIR}/serverconfig.php"
sudo chown root:www-data /etc/yiimp/keys.php
sudo chmod 0640 /etc/yiimp/keys.php
sudo usermod -aG www-data "$(whoami)"

# 7.b: Nginx
# shellcheck disable=SC2016
echo 'map $http_user_agent $blockedagent {
default         0;
~*malicious     1;
~*bot           1;
~*backdoor      1;
~*crawler       1;
~*bandit        1;
}
' | sudo tee /etc/nginx/blockuseragents.rules >/dev/null

# write_nginx_site <0|1>: 1 = HTTPS site with HTTP->HTTPS redirect
write_nginx_site() {
  local ssl="$1" listen tls=""
  if [[ "${ssl}" == 1 ]]; then
    listen='    listen 443 ssl http2;
    listen [::]:443 ssl http2;'
    tls="
    ssl_certificate /etc/letsencrypt/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${SERVER_NAME}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    add_header Strict-Transport-Security \"max-age=31536000\" always;"
  else
    listen='    listen 80;
    listen [::]:80;'
  fi
  {
    echo "include /etc/nginx/blockuseragents.rules;"
    if [[ "${ssl}" == 1 ]]; then
      cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${SERVER_NAMES};
    location ^~ /.well-known/acme-challenge/ { root ${WEB_DIR}; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
    fi
    cat <<EOF
server {
    if (\$blockedagent) { return 403; }
    if (\$request_method !~ ^(GET|HEAD|POST)\$) { return 444; }
${listen}
    server_name ${SERVER_NAMES};
    root ${WEB_DIR};
    index index.php;
    charset utf-8;
${tls}
    add_header X-Content-Type-Options nosniff;
    add_header X-Robots-Tag none;
    add_header Content-Security-Policy "frame-ancestors 'self'";

    access_log off;
    error_log /var/log/nginx/${SERVER_NAME}.app-error.log error;

    client_body_buffer_size 50k;
    client_header_buffer_size 50k;
    client_max_body_size 50k;
    large_client_header_buffers 2 50k;
    sendfile off;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location @rewrite {
        rewrite ^/(.*)\$ /index.php?r=\$1;
    }
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
    location ^~ /.well-known/acme-challenge/ { allow all; }

    location ~ ^/index\.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:${PHP_FPM_SOCK};
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
    }
    location ~ \.php\$ { return 404; }
    location ~ \.sh { return 404; }
    location ~ /\.(?!well-known) { deny all; }
}
EOF
  } | sudo tee "/etc/nginx/sites-available/${SERVER_NAME}.conf" >/dev/null
  sudo ln -sfn "/etc/nginx/sites-available/${SERVER_NAME}.conf" "/etc/nginx/sites-enabled/${SERVER_NAME}.conf"
  sudo nginx -t
  sudo systemctl reload nginx
}

sudo rm -f /etc/nginx/sites-enabled/default
sudo systemctl enable --now nginx
if [[ -f "/etc/letsencrypt/live/${SERVER_NAME}/fullchain.pem" ]]; then
  write_nginx_site 1
else
  write_nginx_site 0
  if is_yes_default "${CONFMAP['SSL_INSTALL']}"; then
    output "Install LetsEncrypt and setting SSL"
    sudo -E apt-get install -y certbot python3-certbot-nginx
    CERTBOT_DOMAINS=()
    for name in ${SERVER_NAMES}; do CERTBOT_DOMAINS+=(-d "${name}"); done
    CERTBOT_EMAIL=(--register-unsafely-without-email)
    [[ -n "${CONFMAP['EMAIL']}" ]] && CERTBOT_EMAIL=(-m "${CONFMAP['EMAIL']}")
    if sudo certbot certonly --webroot -w "${WEB_DIR}" --non-interactive --agree-tos "${CERTBOT_EMAIL[@]}" \
      --deploy-hook "systemctl reload nginx" "${CERTBOT_DOMAINS[@]}"; then
      write_nginx_site 1
    else
      output "WARNING: certbot failed, the site stays on plain HTTP. Re-run the installer once DNS points here."
    fi
  fi
fi
sudo systemctl reload "php${PHP_VER}-fpm"

# Phase 8: Summary #############################################################
# Only lbcd + lbcwallet are running now (started for the wallet address); the rest
# is started by the operator with ~/pool-start.sh. Nothing restarts automatically.

(umask 077 && cat >"${CREDENTIALS_FILE}" <<EOF
LBRY pool install summary ($(date))

Admin panel:      http://${SERVER_NAME}/site/${CONFMAP['ADMIN_PANEL']}  (allowed IPs: ${CONFMAP['PUBLIC_IP']})
Stratum:          stratum+tcp://${SERVER_NAME}:${STRATUM_PORT}  (algo lbry)
Versions:         ${INSTALLED_VERSIONS[*]}, PHP ${PHP_VER}, $(/usr/local/go/bin/go env GOVERSION)
Pool sources:     ${POOL_SRC}

lbcd RPC:         ${LBCD_RPC} (no TLS, localhost only)
lbcwallet RPC:    ${LBCWALLET_RPC} (no TLS, localhost only)
RPC user:         ${SECRETS[LBC_RPCUSER]}
RPC password:     ${SECRETS[LBC_RPCPASS]}
Wallet seed:      ${SEED_FILE}
Pool wallet:      ${MASTER_WALLET:-<not set, configure coins.master_wallet>}
LBC coin id:      ${COIN_ID}

MySQL:            ~/.my.cnf (mysql --defaults-group-suffix=host1 for panel, host2 for stratum)
All secrets:      ${SECRETS_FILE}

Processes run in tmux sessions (root's tmux server); none restart automatically:
  start:          sudo ~/pool-start.sh [all|chain|lbcd|lbcwallet|stratum|blocknotify|web|debug]
  stop:           sudo ~/pool-stop.sh  [same components]   (graceful; lbcd/lbcwallet never force-killed)
  list / attach:  sudo tmux ls / sudo tmux attach -t <session>   (detach: Ctrl-b d)
Sessions:         lbcd lbcwallet stratum blocknotify main loop2 blocks debug
Logs:             ${STRATUM_DIR}/config/*.log, ${YIIMP_LOG_DIR}/debug.log, ${LBCD_DIR}/logs, ${LBCWALLET_DIR}/logs
Chain sync:       lbcctl getblockchaininfo   (stratum mines once lbcd is synced)
Wallet balance:   lbcctl --wallet getbalance
EOF
)

clear
output "LBRY pool installation complete."
output ""
output "Summary and credentials: ${CREDENTIALS_FILE}"
output "Wallet seed (back it up offline, then delete the file): ${SEED_FILE}"
output ""
output "lbcd and lbcwallet are running in tmux (sudo tmux ls) and lbcd is syncing the chain."
output "Check progress with: lbcctl getblockchaininfo"
output "Start stratum, the block notifier and the web loops when ready: sudo ~/pool-start.sh"
output "Stop everything gracefully: sudo ~/pool-stop.sh"
output "Nothing is restarted automatically and nothing starts at boot."
output ""
output "Admin panel: http://${SERVER_NAME}/site/${CONFMAP['ADMIN_PANEL']}"
output "Log out and back in for the www-data group membership to take effect."
