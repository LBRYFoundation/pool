#!/usr/bin/env bash
################################################################################
# Original Author: Oakey22
# Maintained by: Coolguy3289
# Version 2.0 (November 2026)
#
# Program:
#   Install the LBRY (LBC) mining pool on Ubuntu 22.04 / 24.04 / 26.04:
#   Nginx, MariaDB, PHP 8.x (Yii 1.1.32), lbcd + lbcwallet, the LBC-only
#   stratum server and the lbcd WebSocket block notifier (blocknotify-dcr).
#
# Usage:
#   Run from a checkout of this repository as root or a regular user with sudo rights:
#     ./install.sh [-p|--wallet-passphrase <passphrase>]
#   (If run outside a checkout, POOL_REPO / POOL_BRANCH are cloned instead.)
#
# Command-line options:
#   -p, --wallet-passphrase <pass>  passphrase for an existing lbcwallet (to unlock
#                                   it on start and via RPC; also LBC_WALLET_PASS env)
#
# Optional environment overrides:
#   LBC_WALLET_PASS=<pass>    passphrase for an existing lbcwallet
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

# Keep a copy of a config file before it is regenerated (upgrades / re-runs)
BACKUP_STAMP="$(date +%Y%m%d-%H%M%S)"
BACKED_UP=()
backup_file() {
  if sudo test -f "$1"; then
    sudo cp -a "$1" "$1.bak-${BACKUP_STAMP}"
    BACKED_UP+=("$1.bak-${BACKUP_STAMP}")
  fi
}

################################################################################
# Read a key=value option from an INI/conf file (ignores comments and section headers;
# strips inline comments and recognizes bare boolean flags like `notls`)
ini_value() {
  sudo awk -F '=' -v k="$2" '
    /^[ \t]*[#;\[]/ { next }
    {
      line = $0
      sub(/[ \t]+[#;].*$/, "", line)
      pos = index(line, "=")
      if (pos > 0) {
        key = substr(line, 1, pos - 1)
        val = substr(line, pos + 1)
      } else {
        key = line
        val = "true"
      }
      gsub(/^[ \t]+|[ \t\r]+$/, "", key)
      gsub(/^[ \t]+|[ \t\r]+$/, "", val)
      if (key == k) {
        print val
        exit
      }
    }
  ' "$1" 2>/dev/null || true
}

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
SQL_SCHEMA="lbcpool_schema.sql"
SECRETS_FILE="${HOME}/.lbcpool-secrets"
CREDENTIALS_FILE="${HOME}/pool-credentials.txt"
SEED_FILE="${HOME}/lbcwallet-seed.txt"

CLI_WALLET_PASS="${LBC_WALLET_PASS:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p | --wallet-passphrase | --passphrase)
      [[ $# -ge 2 ]] || displayErr "Option $1 requires a passphrase argument."
      CLI_WALLET_PASS="$2"
      shift 2
      ;;
    --wallet-passphrase=* | --passphrase=*)
      CLI_WALLET_PASS="${1#*=}"
      shift
      ;;
    -h | --help)
      echo "Usage: $0 [-p|--wallet-passphrase <passphrase>]"
      exit 0
      ;;
    *)
      displayErr "Unknown option: $1 (Usage: $0 [-p|--wallet-passphrase <passphrase>])"
      ;;
  esac
done

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

if [[ ${EUID} -ne 0 ]]; then
  sudo -v || displayErr "This user needs sudo rights (or run the script as root)."
fi

# shellcheck source=/dev/null
. /etc/os-release
case "${VERSION_ID:-}" in
  22.04 | 24.04 | 26.04) ;;
  *)
    output "WARNING: this installer targets Ubuntu 22.04/24.04/26.04, found ${PRETTY_NAME:-unknown}."
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

# Run mysql as root: ignore ~/.my.cnf (an existing [mysql] password block in
# /root/.my.cnf from the original installer breaks `mysql` with Access denied)
mysql_root() { sudo mysql --no-defaults "$@"; }

# Load file with last configuration data if available
CONF_FILE="${SCRIPT_DIR}/install.conf"
declare -A CONFMAP=()
if [[ -f "${CONF_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${CONF_FILE}"
elif [[ -f "${HOME}/install.conf" && "${HOME}/install.conf" != "${CONF_FILE}" ]]; then
  # The original installer kept its answers next to itself, usually ~/install.conf (same keys)
  output "Using the answers of the previous install from ${HOME}/install.conf"
  # shellcheck source=/dev/null
  source "${HOME}/install.conf"
fi

# Upgrade of an existing pool (original installer or an earlier run of this one)
UPGRADE=0
if [[ -d "${WEB_DIR}/yaamp" || -x "${STRATUM_DIR}/stratum" ]]; then
  UPGRADE=1
  output "Existing pool installation found: running as an upgrade."
  output ""
  # The original installer renamed actionAdminRights() in the deployed SiteController.php;
  # recover that route as the default answer if it is not known yet.
  if [[ -z "${CONFMAP['ADMIN_PANEL']:-}" && -f "${WEB_DIR}/yaamp/modules/site/SiteController.php" ]]; then
    OLD_ACTIONS="$(grep -oP 'public function action\K[A-Za-z0-9]+' "${WEB_DIR}/yaamp/modules/site/SiteController.php" | sort -u || true)"
    NEW_ACTIONS="$(grep -oP 'public function action\K[A-Za-z0-9]+' "${SCRIPT_DIR}/web/yaamp/modules/site/SiteController.php" 2>/dev/null | sort -u || true)"
    ADMIN_CANDIDATES="$(comm -23 <(echo "${OLD_ACTIONS}") <(echo "${NEW_ACTIONS}") | grep . || true)"
    if [[ -n "${ADMIN_CANDIDATES}" && "$(wc -l <<<"${ADMIN_CANDIDATES}")" -eq 1 ]]; then
      CONFMAP['ADMIN_PANEL']="${ADMIN_CANDIDATES}"
      output "Detected the existing admin panel path: /site/${CONFMAP['ADMIN_PANEL']}"
    fi
  fi
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

# Wallet cutover check: only warn if migrating from legacy lbrycrdd (port 14390)
# when no lbcd/lbcwallet is already present on the host.
UPGRADE_NOTES=()
if [[ ${UPGRADE} -eq 1 ]] && command -v mysql &>/dev/null && ! pgrep -x lbcd >/dev/null && ! pgrep -x lbcwallet >/dev/null; then
  LBC_ROW="$(mysql_root -N -e "SELECT id, IFNULL(rpcport,0), IFNULL(program,''), IFNULL(master_wallet,'') FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1" 2>/dev/null || true)"
  if [[ -n "${LBC_ROW}" ]]; then
    read -r OLD_COIN_ID OLD_RPCPORT OLD_PROGRAM OLD_MASTER_WALLET <<<"${LBC_ROW}"
    if [[ "${OLD_RPCPORT}" == "14390" || "${OLD_PROGRAM}" == "lbrycrdd" ]]; then
      IMMATURE_BLOCKS="$(mysql_root -N -e "SELECT COUNT(*) FROM ${DB_NAME}.blocks WHERE coin_id=${OLD_COIN_ID} AND category IN ('new','immature')")"
      PENDING_BALANCE="$(mysql_root -N -e "SELECT IFNULL(ROUND(SUM(balance),8),0) FROM ${DB_NAME}.accounts WHERE coinid=${OLD_COIN_ID}")"
      output "WARNING: this upgrade moves the pool from the lbrycrdd wallet to a new lbcwallet wallet."
      output "  Old pool wallet address:            ${OLD_MASTER_WALLET:-<none>}"
      output "  Blocks still new/immature:          ${IMMATURE_BLOCKS}"
      output "  Unpaid miner balances (LBC):        ${PENDING_BALANCE}"
      output "  - Immature blocks were mined to the old wallet; lbcwallet cannot confirm them, so they"
      output "    would be marked orphan after 7 days and their earnings dropped. Let them mature first."
      output "  - Payouts come from the new wallet: fund it from the old lbrycrdd wallet afterwards."
      read -r -p "Continue with the wallet cutover? [y/N] : " ANSWER
      is_yes "${ANSWER}" || displayErr "Aborted. Let the immature blocks mature (stop stratum ~100 blocks before the cutover), then re-run."
      UPGRADE_NOTES+=("Wallet cutover from lbrycrdd: old address ${OLD_MASTER_WALLET:-<none>}, ${IMMATURE_BLOCKS} immature block(s), ${PENDING_BALANCE} LBC unpaid balances at upgrade time. Fund the new pool wallet from the old lbrycrdd wallet before payouts run.")
    fi
  fi
fi

# Generated secrets are kept so re-running the installer does not break a running pool
declare -A SECRETS=()
if [[ -f "${SECRETS_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${SECRETS_FILE}"
fi
# Always let an existing external lbcd/lbcwallet config win over stale cached RPC credentials
unset "SECRETS[LBC_RPCUSER]" "SECRETS[LBC_RPCPASS]"

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
  PHP_BIN="/usr/bin/php${PHP_VERSION}"
else
  output "Installing the distribution PHP 8.x packages"
  sudo -E apt-get install -y "${PHP_EXTENSIONS[@]/#/php-}"
  # newest PHP 8 CLI now installed (the php-* metapackages follow the default version)
  PHP_BIN="$(find /usr/bin -maxdepth 1 -regex '/usr/bin/php8\.[0-9]+' | sort -V | tail -1)"
fi
[[ -n "${PHP_BIN}" && -x "${PHP_BIN}" ]] || displayErr "PHP 8.x CLI not found after installing the PHP packages."
# Upgraded servers may still have PHP 7.x selected as `php` (web loops and console use `php`)
if [[ "$(readlink -f "$(command -v php)")" != "$(readlink -f "${PHP_BIN}")" ]]; then
  output "Selecting ${PHP_BIN} as the default php CLI"
  sudo update-alternatives --set php "${PHP_BIN}"
fi
PHP_VER="${PHP_BIN#/usr/bin/php}"
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

# Phase 2: Secrets & Existing lbcd/lbcwallet Config Discovery ##################
gen_secret() { pwgen -s 32 1; }

# Discover existing lbcd / lbcwallet / lbrycrd configs and credentials on the host
# so upgrades reuse the active daemon's RPC credentials, TLS settings, and data dir.
EXISTING_LBCD_CONF=""
LBCD_CONF_PATH="${LBCD_DIR}/lbcd.conf"
LBCD_NOTLS=1
LBCD_CERT=""
LBCD_CANDIDATES=(
  "/etc/lbcd/lbcd.conf"
  "${HOME}/.lbcd/lbcd.conf"
  "/root/.lbcd/lbcd.conf"
)
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  SUDO_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
  [[ -n "${SUDO_HOME}" ]] && LBCD_CANDIDATES+=("${SUDO_HOME}/.lbcd/lbcd.conf")
fi
for d in /home/*/.lbcd/lbcd.conf "${LBCD_DIR}/lbcd.conf"; do
  [[ -e "$d" ]] && LBCD_CANDIDATES+=("$d")
done
# If lbcd is currently running with an explicit -C / --configfile=, prefer that first
RUNNING_LBCD_CONF="$(ps -eo args | grep -E '[l]bcd([[:space:]]|$)' | sed -nE 's/.*(-C|--configfile(=|[[:space:]]+))([^[:space:]]+).*/\3/p' | head -1 || true)"
[[ -n "${RUNNING_LBCD_CONF}" ]] && LBCD_CANDIDATES=("${RUNNING_LBCD_CONF}" "${LBCD_CANDIDATES[@]}")

for cand in "${LBCD_CANDIDATES[@]}"; do
  if [[ -n "${cand}" ]] && sudo test -f "${cand}"; then
    cand_user="$(ini_value "${cand}" rpcuser)"
    cand_pass="$(ini_value "${cand}" rpcpass)"
    if [[ -n "${cand_user}" && -n "${cand_pass}" ]]; then
      EXISTING_LBCD_CONF="${cand}"
      LBCD_CONF_PATH="${cand}"
      output "Found existing lbcd config at ${EXISTING_LBCD_CONF}; reusing its RPC credentials."
      SECRETS[LBC_RPCUSER]="${cand_user}"
      SECRETS[LBC_RPCPASS]="${cand_pass}"
      cand_listen="$(ini_value "${cand}" rpclisten)"
      if [[ -n "${cand_listen}" ]]; then
        [[ "${cand_listen}" == :* ]] && cand_listen="127.0.0.1${cand_listen}"
        [[ "${cand_listen}" != *:* ]] && cand_listen="127.0.0.1:${cand_listen}"
        LBCD_RPC="${cand_listen}"
      fi
      cand_notls="$(ini_value "${cand}" notls)"
      if [[ "${cand_notls,,}" =~ ^(1|true|yes)$ ]] ||
         ps -eo args | grep -E '[l]bcd([[:space:]]|$)' | grep -q -- '--notls' ||
         ps -eo args | grep -E '[l]bcwallet([[:space:]]|$)' | grep -q -- '--noclienttls'; then
        LBCD_NOTLS=1
      else
        cand_cert="$(ini_value "${cand}" rpccert)"
        [[ -z "${cand_cert}" ]] && cand_cert="$(dirname "${cand}")/rpc.cert"
        # Probe whether lbcd RPC is actually plain HTTP before assuming TLS from a leftover rpc.cert
        http_code="$(curl -s -k -m 2 -o /dev/null -w '%{http_code}' "http://${LBCD_RPC}/" 2>/dev/null || true)"
        if [[ "${http_code}" == "401" || "${http_code}" == "200" || "${http_code}" == "405" ]]; then
          LBCD_NOTLS=1
        elif sudo test -f "${cand_cert}"; then
          LBCD_NOTLS=0
          LBCD_CERT="${cand_cert}"
        fi
      fi
      break
    fi
  fi
done

# Discover existing lbcwallet config (passphrase, listen port, credentials, appdata)
EXISTING_LBCWALLET_CONF=""
LBCWALLET_CONF_PATH="${LBCWALLET_DIR}/lbcwallet.conf"
LBCWALLET_APPDATA="${LBCWALLET_DIR}"
LBCWALLET_CANDIDATES=(
  "/etc/lbcwallet/lbcwallet.conf"
  "/etc/lbcd/lbcwallet.conf"
  "${HOME}/.lbcwallet/lbcwallet.conf"
  "/root/.lbcwallet/lbcwallet.conf"
  "${LBCWALLET_DIR}/lbcwallet.conf"
)
[[ -n "${SUDO_HOME:-}" ]] && LBCWALLET_CANDIDATES+=("${SUDO_HOME}/.lbcwallet/lbcwallet.conf")
for d in /home/*/.lbcwallet/lbcwallet.conf; do
  [[ -e "$d" ]] && LBCWALLET_CANDIDATES+=("$d")
done
RUNNING_WALLET_CONF="$(ps -eo args | grep -E '[l]bcwallet([[:space:]]|$)' | sed -nE 's/.*(-C|--configfile(=|[[:space:]]+))([^[:space:]]+).*/\3/p' | head -1 || true)"
[[ -n "${RUNNING_WALLET_CONF}" ]] && LBCWALLET_CANDIDATES=("${RUNNING_WALLET_CONF}" "${LBCWALLET_CANDIDATES[@]}")

for cand in "${LBCWALLET_CANDIDATES[@]}"; do
  if [[ -n "${cand}" ]] && sudo test -f "${cand}"; then
    EXISTING_LBCWALLET_CONF="${cand}"
    LBCWALLET_CONF_PATH="${cand}"
    cand_appdata="$(ini_value "${cand}" appdata)"
    [[ -z "${cand_appdata}" ]] && cand_appdata="$(dirname "${cand}")"
    if [[ -n "$(sudo find "${cand_appdata}" -name wallet.db -print -quit 2>/dev/null)" ]]; then
      LBCWALLET_APPDATA="${cand_appdata}"
    fi
    cand_wpass="$(ini_value "${cand}" passphrase)"
    [[ -n "${cand_wpass}" ]] && SECRETS[LBC_WALLET_PASS]="${cand_wpass}"
    if [[ -z "${EXISTING_LBCD_CONF}" ]]; then
      cand_user="$(ini_value "${cand}" rpcuser)"
      cand_pass="$(ini_value "${cand}" rpcpass)"
      if [[ -n "${cand_user}" && -n "${cand_pass}" ]]; then
        output "Found existing lbcwallet config at ${EXISTING_LBCWALLET_CONF}; reusing its RPC credentials."
        SECRETS[LBC_RPCUSER]="${cand_user}"
        SECRETS[LBC_RPCPASS]="${cand_pass}"
      fi
    fi
    cand_wlisten="$(ini_value "${cand}" rpclisten)"
    if [[ -n "${cand_wlisten}" ]]; then
      [[ "${cand_wlisten}" == :* ]] && cand_wlisten="127.0.0.1${cand_wlisten}"
      [[ "${cand_wlisten}" != *:* ]] && cand_wlisten="127.0.0.1:${cand_wlisten}"
      LBCWALLET_RPC="${cand_wlisten}"
    fi
    cand_noclienttls="$(ini_value "${cand}" noclienttls)"
    [[ "${cand_noclienttls,,}" =~ ^(1|true|yes)$ ]] && LBCD_NOTLS=1
    break
  fi
done

# Fallback to legacy lbrycrd.conf or DB coins row if no lbcd/lbcwallet config had credentials yet
if [[ -z "${SECRETS[LBC_RPCUSER]:-}" || -z "${SECRETS[LBC_RPCPASS]:-}" ]]; then
  for cand in "${HOME}/.lbrycrd/lbrycrd.conf" "/root/.lbrycrd/lbrycrd.conf" ${SUDO_HOME:+"${SUDO_HOME}/.lbrycrd/lbrycrd.conf"} /home/*/.lbrycrd/lbrycrd.conf; do
    if [[ -n "${cand}" ]] && sudo test -f "${cand}"; then
      cand_user="$(ini_value "${cand}" rpcuser)"
      cand_pass="$(ini_value "${cand}" rpcpassword)"
      if [[ -n "${cand_user}" && -n "${cand_pass}" ]]; then
        output "Reusing RPC credentials from legacy ${cand}"
        SECRETS[LBC_RPCUSER]="${cand_user}"
        SECRETS[LBC_RPCPASS]="${cand_pass}"
        break
      fi
    fi
  done
fi
if [[ -z "${SECRETS[LBC_RPCUSER]:-}" || -z "${SECRETS[LBC_RPCPASS]:-}" ]] && command -v mysql &>/dev/null; then
  DB_CREDS="$(mysql_root -N -e "SELECT IFNULL(rpcuser,''), IFNULL(rpcpasswd,'') FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1" 2>/dev/null || true)"
  if [[ -n "${DB_CREDS}" ]]; then
    read -r db_u db_p <<<"${DB_CREDS}"
    if [[ -n "${db_u}" && -n "${db_p}" ]]; then
      output "Reusing LBC RPC credentials from database ${DB_NAME}.coins"
      SECRETS[LBC_RPCUSER]="${db_u}"
      SECRETS[LBC_RPCPASS]="${db_p}"
    fi
  fi
fi

# Also reuse existing stratum / DB passwords on upgrade if present
if [[ -z "${SECRETS[STRATUM_PASSWORD]:-}" ]] && sudo test -f "${STRATUM_DIR}/config/lbry.conf"; then
  old_sp="$(sudo awk -F '=' '/^\[TCP\]/{f=1;next} /^\[/{f=0} f && $1 ~ /^[ \t]*password[ \t]*$/ {gsub(/^[ \t]+|[ \t\r]+$/,"",$2); print $2; exit}' "${STRATUM_DIR}/config/lbry.conf" 2>/dev/null || true)"
  [[ -n "${old_sp}" && "${old_sp}" != "tu8tu5" ]] && SECRETS[STRATUM_PASSWORD]="${old_sp}"
fi
if [[ -z "${SECRETS[MYSQL_STRATUMPASSWD]:-}" ]] && sudo test -f "${STRATUM_DIR}/config/lbry.conf"; then
  old_mp="$(sudo awk -F '=' '/^\[SQL\]/{f=1;next} /^\[/{f=0} f && $1 ~ /^[ \t]*password[ \t]*$/ {gsub(/^[ \t]+|[ \t\r]+$/,"",$2); print $2; exit}' "${STRATUM_DIR}/config/lbry.conf" 2>/dev/null || true)"
  [[ -n "${old_mp}" && "${old_mp}" != "patofpaq" ]] && SECRETS[MYSQL_STRATUMPASSWD]="${old_mp}"
fi

# If a wallet passphrase was passed via CLI (-p / --wallet-passphrase) or LBC_WALLET_PASS env,
# it overrides any cached or discovered passphrase.
if [[ -n "${CLI_WALLET_PASS}" ]]; then
  SECRETS[LBC_WALLET_PASS]="${CLI_WALLET_PASS}"
fi
# If an existing wallet.db was discovered without a passphrase configured anywhere,
# default to lbcwallet's built-in default ("passphrase") rather than a random string.
if [[ -z "${SECRETS[LBC_WALLET_PASS]:-}" ]] && [[ -n "$(sudo find "${LBCWALLET_APPDATA}" -name wallet.db -print -quit 2>/dev/null)" ]]; then
  SECRETS[LBC_WALLET_PASS]="passphrase"
fi

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
# Remove only non-chain systemd units left behind by an earlier installer version;
# never stop a running lbcd or lbcwallet during install (lbcd can take 30+ min to reload).
for unit in lbc-blocknotify lbc-stratum yiimp-main yiimp-loop2 yiimp-blocks; do
  if [[ -f "/etc/systemd/system/${unit}.service" ]]; then
    output "Removing legacy systemd unit ${unit}.service"
    sudo systemctl disable --now "${unit}.service" || true
    sudo rm -f "/etc/systemd/system/${unit}.service"
  fi
done
sudo systemctl daemon-reload
if pgrep -x lbcd >/dev/null; then
  output "lbcd is already running; keeping it running."
fi
if pgrep -x lbcwallet >/dev/null; then
  output "lbcwallet is already running; keeping it running."
fi
install_lbry_release lbryio/lbcd lbcd "${LBCD_VERSION:-latest}" lbcd lbcctl
install_lbry_release lbryio/lbcwallet lbcwallet "${LBCWALLET_VERSION:-latest}" lbcwallet

# Dedicated service user
if ! id lbc &>/dev/null; then
  sudo useradd --system --home-dir "${LBC_HOME}" --create-home --shell /usr/sbin/nologin lbc
fi
sudo install -d -o lbc -g lbc -m 0750 "${LBC_HOME}" "${LBCD_DIR}" "${LBCWALLET_DIR}"
sudo install -d -m 0750 -o root -g lbc "${POOL_ETC}"

# lbcd config: preserve an existing external lbcd.conf (e.g. /etc/lbcd/lbcd.conf or ~/.lbcd/lbcd.conf);
# also write ${LBCD_DIR}/lbcd.conf with the active credentials.
if [[ "${LBCD_NOTLS}" == 1 ]]; then
  LBCD_TLS_LINE="notls=1"
  LBCWALLET_CLIENT_TLS_LINE="noclienttls=1"
  LBCCTL_TLS_LINE="notls=1"
else
  sudo cp -a "${LBCD_CERT}" "${POOL_ETC}/lbcd-rpc.cert" 2>/dev/null || true
  sudo chown root:lbc "${POOL_ETC}/lbcd-rpc.cert" 2>/dev/null || true
  sudo chmod 0640 "${POOL_ETC}/lbcd-rpc.cert" 2>/dev/null || true
  LBCD_TLS_LINE="rpccert=${LBCD_CERT}"
  LBCWALLET_CLIENT_TLS_LINE="cafile=${LBCD_CERT}"
  LBCCTL_TLS_LINE="rpccert=${LBCD_CERT}"
fi

if [[ -z "${EXISTING_LBCD_CONF}" || "${EXISTING_LBCD_CONF}" == "${LBCD_DIR}/lbcd.conf" ]]; then
  backup_file "${LBCD_DIR}/lbcd.conf"
  sudo tee "${LBCD_DIR}/lbcd.conf" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
rpclisten=${LBCD_RPC}
${LBCD_TLS_LINE}
txindex=1
EOF
  sudo chown lbc:lbc "${LBCD_DIR}/lbcd.conf"
  sudo chmod 0600 "${LBCD_DIR}/lbcd.conf"
  LBCD_CONF_PATH="${LBCD_DIR}/lbcd.conf"
fi

# lbcwallet: uses the same credentials for its own RPC server and for lbcd;
# stratum and the web backend talk to lbcwallet, which proxies chain RPCs to lbcd.
WALLET_OWNER="$(sudo stat -c '%U' "${LBCWALLET_APPDATA}" 2>/dev/null || echo lbc)"
if ! pgrep -x lbcwallet >/dev/null || ! sudo test -f "${LBCWALLET_CONF_PATH}" || [[ -n "${CLI_WALLET_PASS}" ]]; then
  backup_file "${LBCWALLET_CONF_PATH}"
  sudo install -d -m 0750 "$(dirname "${LBCWALLET_CONF_PATH}")"
  sudo tee "${LBCWALLET_CONF_PATH}" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
rpcconnect=${LBCD_RPC}
${LBCWALLET_CLIENT_TLS_LINE}
rpclisten=${LBCWALLET_RPC}
noservertls=1
passphrase=${SECRETS[LBC_WALLET_PASS]}
EOF
  sudo chown "${WALLET_OWNER}:${WALLET_OWNER}" "${LBCWALLET_CONF_PATH}" 2>/dev/null || true
  sudo chmod 0600 "${LBCWALLET_CONF_PATH}"
else
  output "Keeping existing ${LBCWALLET_CONF_PATH} (lbcwallet is already running)."
fi

# Create the pool wallet once; the seed is written to SEED_FILE for the operator to back up
wallet_exists() { [[ -n "$(sudo find "${LBCWALLET_APPDATA}" -name wallet.db -print -quit 2>/dev/null)" ]]; }
if ! pgrep -x lbcwallet >/dev/null && ! wallet_exists; then
  output "Creating the pool wallet"
  CREATE_OUT="$(mktemp)"
  # shellcheck disable=SC2024 # output file is intentionally owned by the installing user
  (printf 'no\n' | sudo -u "${WALLET_OWNER}" /usr/local/bin/lbcwallet -C "${LBCWALLET_CONF_PATH}" \
    -A "${LBCWALLET_APPDATA}" --create >"${CREATE_OUT}" 2>&1) &
  CREATE_PID=$!
  for _ in $(seq 1 90); do
    wallet_exists && break
    kill -0 "${CREATE_PID}" 2>/dev/null || break
    sleep 1
  done
  sleep 3
  sudo pkill -u "${WALLET_OWNER}" -f 'lbcwallet.*--create' 2>/dev/null || true
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
    output "Create it manually: sudo -u ${WALLET_OWNER} lbcwallet -C ${LBCWALLET_CONF_PATH} -A ${LBCWALLET_APPDATA} --create"
  fi
  rm -f "${CREATE_OUT}"
fi

# lbcctl convenience config for the operator: `lbcctl getblockchaininfo`, `lbcctl --wallet getbalance`
install -d -m 0700 "${HOME}/.lbcctl"
(umask 077 && cat >"${HOME}/.lbcctl/lbcctl.conf" <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
${LBCCTL_TLS_LINE}
EOF
)
# Wallet RPC always runs with noservertls=1 on localhost
lbcctl_wallet() { lbcctl -C "${HOME}/.lbcctl/lbcctl.conf" --notls --wallet -s "${LBCWALLET_RPC}" "$@"; }

# Phase 5: Database ############################################################
clear
output "Now for the database fun!"
output ""
sudo systemctl enable --now mariadb

# MariaDB root uses unix_socket auth on Ubuntu, so `mysql_root` needs no password.
# Pool users only get privileges on the pool database.
mysql_root <<EOF
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
backup_file "${HOME}/.my.cnf"
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

TABLE_COUNT="$(mysql_root -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'")"
if [[ "${TABLE_COUNT}" -eq 0 ]]; then
  output "Performing the SQL import (${SQL_SCHEMA})"
  import_sql <"${POOL_SRC}/sql/${SQL_SCHEMA}"
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
# Sourced by pool-start.sh for blocknotify-dcr and lbcwallet unlocking;
# STRATUM_PASSWORD is inherited by the blocknotify child process
sudo tee "${POOL_ETC}/blocknotify.env" >/dev/null <<EOF
LBCD_RPCUSER=${SECRETS[LBC_RPCUSER]}
LBCD_RPCPASS=${SECRETS[LBC_RPCPASS]}
LBC_WALLET_PASS=${SECRETS[LBC_WALLET_PASS]}
STRATUM_PASSWORD=${SECRETS[STRATUM_PASSWORD]}
EOF
# lbcctl config used by pool-start.sh to wait for lbcd's RPC
sudo tee "${POOL_ETC}/lbcctl.conf" >/dev/null <<EOF
[Application Options]
rpcuser=${SECRETS[LBC_RPCUSER]}
rpcpass=${SECRETS[LBC_RPCPASS]}
${LBCCTL_TLS_LINE}
EOF
# Non-secret settings for pool-start.sh (COIN_ID is updated once the coin record exists)
write_pool_env() {
  sudo tee "${POOL_ETC}/pool.env" >/dev/null <<EOF
COIN_ID=${1:-}
LBCD_RPC=${LBCD_RPC}
LBCWALLET_RPC=${LBCWALLET_RPC}
LBCD_CONF=${LBCD_CONF_PATH}
LBCWALLET_CONF=${LBCWALLET_CONF_PATH}
LBCWALLET_APPDATA=${LBCWALLET_APPDATA}
LBCD_NOTLS=${LBCD_NOTLS}
LBCD_CERT=${LBCD_CERT:+${POOL_ETC}/lbcd-rpc.cert}
EOF
}
write_pool_env ""
sudo chown root:lbc "${POOL_ETC}/blocknotify.env" "${POOL_ETC}/lbcctl.conf" "${POOL_ETC}/pool.env"
sudo chmod 0640 "${POOL_ETC}/blocknotify.env" "${POOL_ETC}/lbcctl.conf" "${POOL_ETC}/pool.env"

# Start/stop helpers: every process runs in its own tmux session (root's tmux
# server) and is never restarted automatically.
install -m 0755 "${POOL_SRC}/bin/pool-start.sh" "${HOME}/pool-start.sh"
install -m 0755 "${POOL_SRC}/bin/pool-stop.sh" "${HOME}/pool-stop.sh"

# lbcd + lbcwallet are needed now to get the pool wallet address;
# if they are already running, pool-start.sh leaves them untouched and continues immediately.
sudo "${HOME}/pool-start.sh" chain

# Pool wallet address (Base58 legacy; stratum needs a b.../r... address when
# lbcwallet does not return witness_version/witness_program in validateaddress).
# Do not block the installer if lbcd/lbcwallet are still loading (can take 30+ min).
MASTER_WALLET="$(mysql_root -N -e "SELECT IFNULL(master_wallet,'') FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1" || true)"
WALLET_RPC_READY=0
for _ in $(seq 1 5); do
  if lbcctl_wallet getinfo >/dev/null 2>&1; then
    WALLET_RPC_READY=1
    break
  fi
  sleep 1
done

if [[ "${WALLET_RPC_READY}" == 1 ]]; then
  # Only unlock if walletislocked reports true (calling walletpassphrase on an already-unlocked
  # wallet overrides lbcwallet's indefinite startup unlock with a temporary timeout)
  if [[ -n "${SECRETS[LBC_WALLET_PASS]:-}" ]] && [[ "$(lbcctl_wallet walletislocked 2>/dev/null || true)" == "true" ]]; then
    lbcctl_wallet walletpassphrase "${SECRETS[LBC_WALLET_PASS]}" 315360000 >/dev/null 2>&1 || true
  fi
  if [[ -n "${MASTER_WALLET}" ]]; then
    # An existing address (e.g. from the old lbrycrdd wallet) is only kept if lbcwallet owns it;
    # stratum refuses to mine to a pool address that is not "ismine".
    ISMINE="$(lbcctl_wallet validateaddress "${MASTER_WALLET}" 2>/dev/null | jq -r '.ismine // empty' 2>/dev/null || true)"
    if [[ "${ISMINE}" == "true" ]]; then
      output "Keeping pool wallet address ${MASTER_WALLET} (owned by lbcwallet)"
    elif [[ "${ISMINE}" == "false" ]]; then
      output "Pool wallet address ${MASTER_WALLET} is not owned by lbcwallet, replacing it"
      UPGRADE_NOTES+=("Pool wallet address changed: ${MASTER_WALLET} (not in lbcwallet) was replaced.")
      MASTER_WALLET=""
    fi
  fi
  if [[ -z "${MASTER_WALLET}" ]]; then
    output "Requesting a pool wallet address from lbcwallet"
    MASTER_WALLET="$(lbcctl_wallet getnewaddress default legacy 2>/dev/null || true)"
    [[ "${MASTER_WALLET}" =~ ^[br][1-9A-HJ-NP-Za-km-z]{25,40}$ ]] || MASTER_WALLET=""
    [[ -n "${MASTER_WALLET}" ]] || output "WARNING: could not get a wallet address; set coins.master_wallet for LBC in the admin panel"
  fi
else
  output "lbcwallet RPC is not ready yet (lbcd may still be starting or syncing); continuing without waiting."
  if [[ -n "${MASTER_WALLET}" ]]; then
    output "Keeping existing master_wallet ${MASTER_WALLET} in database."
  else
    output "Once lbcd and lbcwallet finish starting, set coins.master_wallet (or re-run ./install.sh)."
  fi
fi

# LBC coin row: stratum/web talk to lbcwallet (wallet RPCs) and lbcd (mining RPCs).
# rpccurl=1 is required because lbcwallet/lbcd use HTTP chunked transfer encoding.
mysql_root "${DB_NAME}" <<EOF
INSERT INTO coins (name, symbol, algo, image, enable, auto_ready, visible, installed,
  rpchost, rpcport, rpcuser, rpcpasswd, rpcencoding, rpccurl, rpcssl, account,
  hassubmitblock, hasgetinfo, usesegwit, txmessage, mature_blocks, block_time,
  conf_folder, program, link_site, link_github)
SELECT 'LBRY Credits', 'LBC', 'lbry', '/images/coin-LBRY.png', 1, 1, 1, 1,
  '127.0.0.1', ${LBCWALLET_RPC##*:}, '${SECRETS[LBC_RPCUSER]}', '${SECRETS[LBC_RPCPASS]}', 'LBC', 1, 0, 'default',
  1, 1, 1, 0, 100, 150,
  '${LBCWALLET_DIR}', 'lbcwallet', 'https://lbry.com', 'https://github.com/lbryio/lbcd'
FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM coins WHERE symbol='LBC');
UPDATE coins SET algo='lbry', rpchost='127.0.0.1', rpcport=${LBCWALLET_RPC##*:},
  rpcuser='${SECRETS[LBC_RPCUSER]}', rpcpasswd='${SECRETS[LBC_RPCPASS]}',
  rpcencoding='LBC', rpccurl=1, rpcssl=0, rpccert=NULL, installed=1, hasgetinfo=1,
  account=IF(IFNULL(account,'')='', 'default', account),
  conf_folder='${LBCWALLET_DIR}', program='lbcwallet'
  WHERE symbol='LBC';
UPDATE coins SET master_wallet='${MASTER_WALLET}' WHERE symbol='LBC' AND '${MASTER_WALLET}' <> '';
EOF
COIN_ID="$(mysql_root -N -e "SELECT id FROM ${DB_NAME}.coins WHERE symbol='LBC' LIMIT 1")"
[[ -n "${COIN_ID}" ]] || displayErr "Could not create the LBC coin record."
write_pool_env "${COIN_ID}"

# Stratum config (written in full; the old sed edits did not match config.sample).
# Tuned values of an existing config are carried over.
STRATUM_DIFF=128
STRATUM_MAX_TTF=40000000
if sudo test -f "${STRATUM_DIR}/config/lbry.conf"; then
  OLD_VALUE="$(ini_value "${STRATUM_DIR}/config/lbry.conf" difficulty)"
  [[ "${OLD_VALUE}" =~ ^[0-9]+(\.[0-9]+)?$ ]] && STRATUM_DIFF="${OLD_VALUE}"
  OLD_VALUE="$(ini_value "${STRATUM_DIR}/config/lbry.conf" max_ttf)"
  [[ "${OLD_VALUE}" =~ ^[0-9]+$ ]] && STRATUM_MAX_TTF="${OLD_VALUE}"
fi
backup_file "${STRATUM_DIR}/config/lbry.conf"
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
difficulty = ${STRATUM_DIFF}
max_ttf = ${STRATUM_MAX_TTF}
coinbase_sig = ${CONFMAP['COINBASE_SIG']}
EOF
sudo chmod 0640 "${STRATUM_DIR}/config/lbry.conf"
sudo chown -R www-data:www-data "${STRATUM_DIR}"

# Phase 7: Web #################################################################
clear
output "Making Web Server Magic Happen!"
output ""

sudo install -d -m 0755 "${WEB_DIR}"
# images/ is protected from deletion: the backend downloads coin images into it
sudo rsync -a --delete \
  --exclude 'serverconfig.php' --exclude 'yaamp/runtime/***' --exclude 'assets/***' \
  --filter 'P images/***' \
  "${POOL_SRC}/web/" "${WEB_DIR}/"
sudo install -d "${WEB_DIR}/yaamp/runtime" "${WEB_DIR}/assets"
# custom admin entrance (applied to the deployed copy, not the git checkout)
sudo sed -i "s/AdminRights/${CONFMAP['ADMIN_PANEL']}/" "${WEB_DIR}/yaamp/modules/site/SiteController.php"
# `yiimp` console helper expects ROOTDIR/web
sudo install -d /var/yiimp
sudo ln -sfn "${WEB_DIR}" /var/yiimp/web

sudo install -d -o www-data -g www-data -m 2775 "${YIIMP_LOG_DIR}" "${BACKUP_DIR}"
sudo touch "${YIIMP_LOG_DIR}/debug.log" "${YIIMP_LOG_DIR}/rental.log"
sudo chown -R www-data:www-data "${YIIMP_LOG_DIR}" "${BACKUP_DIR}"
sudo chmod 0664 "${YIIMP_LOG_DIR}"/*.log 2>/dev/null || true
sudo chown -R www-data:www-data "${WEB_DIR}/yaamp/runtime" "${WEB_DIR}/assets"
sudo chmod -R 2775 "${WEB_DIR}/yaamp/runtime" "${WEB_DIR}/assets"

# Operator settings (as PHP literals); values from an existing serverconfig.php win
declare -A WEBCFG=(
  [YAAMP_SITE_NAME]="'LBRY Pool'" [YAAMP_STRATUM_URL]="YAAMP_SITE_URL"
  [YAAMP_FEES_MINING]="0.5" [YAAMP_PAYMENTS_FREQ]="3*60*60" [YAAMP_PAYMENTS_MINI]="0.001"
  [YIIMP_PUBLIC_EXPLORER]="true" [YIIMP_PUBLIC_BENCHMARK]="false" [YIIMP_FIAT_ALTERNATIVE]="'USD'"
  [cold_wallet_table]="array()" [configFixedPoolFees]="array()"
  [configCustomPorts]="array()" [configAlgoNormCoef]="array()"
)
if sudo test -f "${WEB_DIR}/serverconfig.php"; then
  output "Carrying over settings from the existing serverconfig.php"
  backup_file "${WEB_DIR}/serverconfig.php"
  READ_CFG="$(mktemp --suffix=.php)"
  cat >"${READ_CFG}" <<'PHP'
<?php
// usage: php read.php <serverconfig.php> <name>... -> "name<TAB>php literal" per line
ob_start();
try { include $argv[1]; } catch (Throwable $e) { }
ob_end_clean();
foreach (array_slice($argv, 2) as $name) {
	if (defined($name)) {
		$value = constant($name);
		// keep the YAAMP_SITE_URL expression unless the stratum host differs
		if ($name === 'YAAMP_STRATUM_URL' && defined('YAAMP_SITE_URL') && $value === YAAMP_SITE_URL) continue;
	} elseif (isset($GLOBALS[$name]) && is_array($GLOBALS[$name])) {
		$value = $GLOBALS[$name];
	} else {
		continue;
	}
	echo $name, "\t", str_replace(array("\r", "\n", "\t"), ' ', var_export($value, true)), "\n";
}
PHP
  chmod 0644 "${READ_CFG}"
  while IFS=$'\t' read -r key value; do
    [[ -n "${key}" && -n "${value}" && -n "${WEBCFG[${key}]+x}" ]] && WEBCFG[${key}]="${value}"
  done < <(sudo php -d display_errors=0 -d error_reporting=0 "${READ_CFG}" "${WEB_DIR}/serverconfig.php" "${!WEBCFG[@]}" || true)
  rm -f "${READ_CFG}"
fi

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

define('YAAMP_FEES_MINING', ${WEBCFG[YAAMP_FEES_MINING]});
define('YAAMP_PAYMENTS_FREQ', ${WEBCFG[YAAMP_PAYMENTS_FREQ]});
define('YAAMP_PAYMENTS_MINI', ${WEBCFG[YAAMP_PAYMENTS_MINI]});

define('YIIMP_PUBLIC_EXPLORER', ${WEBCFG[YIIMP_PUBLIC_EXPLORER]});
define('YIIMP_PUBLIC_BENCHMARK', ${WEBCFG[YIIMP_PUBLIC_BENCHMARK]});
define('YIIMP_FIAT_ALTERNATIVE', ${WEBCFG[YIIMP_FIAT_ALTERNATIVE]});

define('YAAMP_SITE_URL', '${SERVER_NAME}');
define('YAAMP_STRATUM_URL', ${WEBCFG[YAAMP_STRATUM_URL]}); // change if your stratum server is on a different host
define('YAAMP_SITE_NAME', ${WEBCFG[YAAMP_SITE_NAME]});
define('YAAMP_ADMIN_EMAIL', '${CONFMAP['EMAIL']}');
define('YAAMP_ADMIN_IP', '${CONFMAP['PUBLIC_IP']}'); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
define('YAAMP_ADMIN_WEBCONSOLE', true);
define('YAAMP_NOTIFY_NEW_COINS', false);
define('YAAMP_CREATE_NEW_COINS', false);
define('YAAMP_DEFAULT_ALGO', 'lbry');
define('YAAMP_USE_NGINX', true);

define('LBC_DAEMON_HOST', '${LBCD_RPC%:*}');
define('LBC_DAEMON_PORT', ${LBCD_RPC##*:});
define('LBC_DAEMON_SSL', $([[ "${LBCD_NOTLS}" == 1 ]] && echo false || echo true));
define('LBC_DAEMON_CERT', '${LBCD_CERT:+${POOL_ETC}/lbcd-rpc.cert}');

\$cold_wallet_table = ${WEBCFG[cold_wallet_table]};
\$configFixedPoolFees = ${WEBCFG[configFixedPoolFees]};
\$configCustomPorts = ${WEBCFG[configCustomPorts]};
\$configAlgoNormCoef = ${WEBCFG[configAlgoNormCoef]};
EOF
sudo php -l "${WEB_DIR}/serverconfig.php" >/dev/null ||
  displayErr "Generated ${WEB_DIR}/serverconfig.php is invalid; the previous one is in ${WEB_DIR}/serverconfig.php.bak-${BACKUP_STAMP}"

# mysqldump credentials for the web backup job
sudo install -d -m 0755 /etc/yiimp
backup_file /etc/yiimp/keys.php
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

# Allow www-data (used by the main/loop2/blocks backend processes) to stop/start
# nginx non-interactively during payouts and monitorApache() without prompting for a password.
sudo tee /etc/sudoers.d/lbcpool-nginx >/dev/null <<'EOF'
www-data ALL=(root) NOPASSWD: /usr/sbin/service nginx start, /usr/sbin/service nginx stop, /usr/sbin/service nginx reload, /usr/sbin/service nginx restart, /bin/systemctl start nginx, /bin/systemctl stop nginx, /bin/systemctl reload nginx, /bin/systemctl restart nginx
EOF
sudo chmod 0440 /etc/sudoers.d/lbcpool-nginx

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

# Find an existing Let's Encrypt live certificate directory for SERVER_NAME
# (handles /etc/letsencrypt/live/<domain>-0001 and mode 0700 /etc/letsencrypt/live)
find_letsencrypt_cert_dir() {
  local d
  while IFS= read -r d; do
    [[ -n "${d}" ]] || continue
    if sudo test -f "${d}/fullchain.pem" && sudo test -f "${d}/privkey.pem"; then
      echo "${d}"
      return 0
    fi
  done < <(sudo find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 \( -name "${SERVER_NAME}" -o -name "${SERVER_NAME}-*" \) 2>/dev/null | sort -V)
  return 1
}

# write_nginx_site <0|1> [cert_dir]: 1 = HTTPS site with HTTP->HTTPS redirect
write_nginx_site() {
  local ssl="$1" cert_dir="${2:-/etc/letsencrypt/live/${SERVER_NAME}}" listen tls=""
  if [[ "${ssl}" == 1 ]]; then
    listen='    listen 443 ssl http2;
    listen [::]:443 ssl http2;'
    tls="
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
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

backup_file "/etc/nginx/sites-available/${SERVER_NAME}.conf"
sudo rm -f /etc/nginx/sites-enabled/default
# Remove any stale sites-enabled configs that conflict on server_name
for enabled_site in /etc/nginx/sites-enabled/*; do
  [[ -e "${enabled_site}" ]] || continue
  [[ "$(basename "${enabled_site}")" == "${SERVER_NAME}.conf" ]] && continue
  if sudo grep -qF "${SERVER_NAME}" "${enabled_site}" 2>/dev/null; then
    sudo rm -f "${enabled_site}"
  fi
done
sudo systemctl enable --now nginx
LE_CERT_DIR="$(find_letsencrypt_cert_dir || true)"
if [[ -n "${LE_CERT_DIR}" ]]; then
  output "Using existing Let's Encrypt certificate in ${LE_CERT_DIR}"
  write_nginx_site 1 "${LE_CERT_DIR}"
else
  write_nginx_site 0
  if is_yes_default "${CONFMAP['SSL_INSTALL']}"; then
    output "Install LetsEncrypt and setting SSL"
    sudo -E apt-get install -y certbot python3-certbot-nginx
    CERTBOT_EMAIL=(--register-unsafely-without-email)
    [[ -n "${CONFMAP['EMAIL']}" ]] && CERTBOT_EMAIL=(-m "${CONFMAP['EMAIL']}")
    # Request certificate for SERVER_NAME (and www.SERVER_NAME if it resolves; fall back to SERVER_NAME alone if www DNS is missing)
    CERTBOT_DOMAINS=(-d "${SERVER_NAME}")
    for name in ${SERVER_NAMES}; do
      [[ "${name}" == "${SERVER_NAME}" ]] && continue
      CERTBOT_DOMAINS+=(-d "${name}")
    done
    if sudo certbot certonly --webroot -w "${WEB_DIR}" --non-interactive --agree-tos --keep-until-expiring "${CERTBOT_EMAIL[@]}" \
      --deploy-hook "systemctl reload nginx" "${CERTBOT_DOMAINS[@]}" ||
       { [[ "${#CERTBOT_DOMAINS[@]}" -gt 2 ]] && sudo certbot certonly --webroot -w "${WEB_DIR}" --non-interactive --agree-tos --keep-until-expiring "${CERTBOT_EMAIL[@]}" \
         --deploy-hook "systemctl reload nginx" -d "${SERVER_NAME}"; }; then
      LE_CERT_DIR="$(find_letsencrypt_cert_dir || echo "/etc/letsencrypt/live/${SERVER_NAME}")"
      write_nginx_site 1 "${LE_CERT_DIR}"
    else
      output "WARNING: certbot failed, the site stays on plain HTTP. Re-run the installer once DNS points here."
    fi
  fi
fi
sudo systemctl reload "php${PHP_VER}-fpm"

# Phase 8: Summary #############################################################
# Only lbcd + lbcwallet are running now (started for the wallet address); the rest
# is started by the operator with ~/pool-start.sh. Nothing restarts automatically.

(umask 077 && {
cat <<EOF
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
  if [[ ${UPGRADE} -eq 1 ]]; then
    echo
    echo "Upgrade notes:"
    for note in "${UPGRADE_NOTES[@]}"; do echo "  - ${note}"; done
    echo "  - Previous config files were kept as:"
    for f in "${BACKED_UP[@]}"; do echo "      ${f}"; done
    echo "  - The legacy lbrycrdd data (~/.lbrycrd) and binaries were left untouched."
  fi
} >"${CREDENTIALS_FILE}")

clear
output "LBRY pool installation complete."
output ""
output "Summary and credentials: ${CREDENTIALS_FILE}"
output "Wallet seed (back it up offline, then delete the file): ${SEED_FILE}"
output ""
if [[ ${UPGRADE} -eq 1 ]]; then
  output "Upgrade notes:"
  for note in "${UPGRADE_NOTES[@]}"; do output "  - ${note}"; done
  output "  - ${#BACKED_UP[@]} previous config file(s) backed up (*.bak-${BACKUP_STAMP}), see ${CREDENTIALS_FILE}"
  output ""
fi
output "lbcd and lbcwallet are running in tmux (sudo tmux ls) and lbcd is syncing the chain."
output "Check progress with: lbcctl getblockchaininfo"
output "Start stratum, the block notifier and the web loops when ready: sudo ~/pool-start.sh"
output "Stop everything gracefully: sudo ~/pool-stop.sh"
output "Nothing is restarted automatically and nothing starts at boot."
output ""
output "Admin panel: http://${SERVER_NAME}/site/${CONFMAP['ADMIN_PANEL']}"
output "Log out and back in for the www-data group membership to take effect."
