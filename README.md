# Lbry Mining Pool based on Yiimp
# Home Codebase of [LBRYPool](https://lbrypool.net)

An LBC-only mining pool: the yiimp web front-end (Yii 1.1.32 on PHP 8.x), the
`lbry` algo stratum server, and [lbcd](https://github.com/lbryio/lbcd) +
[lbcwallet](https://github.com/lbryio/lbcwallet).

## Prerequisites:
1. Ubuntu 22.04 or 24.04 (amd64 or arm64)
2. A domain name pointed at the server (for LetsEncrypt SSL)
3. Install Script (Provided in this repo)

WARNINGS
- Use at your own risks.

The install script installs the pool and all dependencies, always fetching the
newest releases: distribution PHP 8.x, MariaDB, Nginx, the latest Go toolchain
(checksum-verified from go.dev) and the latest lbcd/lbcwallet GitHub releases
(checksum-verified against the release `checksums.txt`).

TO INSTALL:
1. Log in to your server
2. Create new user - `sudo adduser (username)`
3. Add user to sudo group - `sudo adduser (username) sudo`
4. Log in to new user - `sudo su - (username)`
5. `git clone https://github.com/LBRYFoundation/pool.git && cd pool`
   (add `--branch <branch>` to test a branch)
6. `./install.sh`
7. Follow the instructions on the screen.

Optional environment overrides (e.g. `PHP_VERSION=8.4 ./install.sh`):

| Variable | Effect |
|---|---|
| `PHP_VERSION` | install that PHP version from `ppa:ondrej/php` instead of the distribution's PHP 8.x |
| `LBCD_VERSION` / `LBCWALLET_VERSION` | pin a release tag, e.g. `v0.22.119` (default: latest) |
| `GO_VERSION` | pin the Go toolchain, e.g. `go1.27.4` (default: latest stable) |
| `POOL_REPO` / `POOL_BRANCH` | what to clone when `install.sh` is run outside a checkout |

The installer can be re-run (e.g. to upgrade lbcd/lbcwallet/PHP): answers are kept
in `install.conf` and generated passwords in `~/.lbcpool-secrets`.

## Upgrading a pool installed with the original installer

Stop the old processes (tmux/screen sessions, `lbrycrdd`), then run `./install.sh`
from a checkout of this repository. The installer detects the existing install and:

- reuses the answers from `~/install.conf` and pre-fills the existing custom admin path;
- keeps the database, applies the new `sql/2026-*` migrations, and repoints the LBC
  coin record from lbrycrdd to lbcwallet;
- keeps the existing pool address only if the new lbcwallet owns it; otherwise it
  requests a new one;
- carries over operator settings from `serverconfig.php` (site name, fees, payout
  settings, stratum URL, fee/port tables) and the stratum `difficulty`/`max_ttf`;
- backs up every config file it rewrites as `<file>.bak-<timestamp>`;
- switches the `php` CLI to PHP 8 if an older PHP is still selected.

**Wallet cutover:** the original pool used the lbrycrdd wallet, which lbcwallet cannot
see. Before upgrading, let found blocks mature (stop stratum ~100 blocks / ~4 hours
before the cutover); otherwise lbcwallet cannot confirm them, and they are marked
orphan after 7 days. After upgrading, fund the new pool wallet from the old lbrycrdd
wallet before payouts run. The installer shows the number of immature blocks and the
unpaid balances and asks for confirmation. `~/.lbrycrd` is left untouched.

## What gets installed

| Component | Details |
|---|---|
| `lbcd` | LBRY full node, RPC on `127.0.0.1:9245` (localhost only, no TLS), P2P port 9246 |
| `lbcwallet` | Pool wallet, RPC on `127.0.0.1:9244`; proxies chain RPCs to lbcd |
| `stratum` | Stratum server on port 3334 (`/var/stratum`, config `/var/stratum/config/lbry.conf`) |
| `blocknotify` | `blocknotify-dcr`: subscribes to lbcd block notifications and notifies stratum |
| `main`, `loop2`, `blocks` | Web backend loops (`web/main.sh`, `loop2.sh`, `blocks.sh`) |
| `debug` | `tail -F /var/log/yiimp/debug.log` |
| Database | MariaDB database `yiimpfrontend` with users `panel` (web) and `stratum` |

The installer also creates the LBC coin record (algo `lbry`, RPC pointing at
lbcwallet), creates the pool wallet and requests a Base58 (legacy) pool address,
so no manual coin setup is needed in the admin panel.

## Running the pool

The pool processes are **not** systemd services. Each runs in its own tmux
session (in root's tmux server), so nothing restarts them behind your back and
nothing starts at boot. If a process exits, its session stays open and shows the
exit code.

	sudo ~/pool-start.sh                 # start everything, in dependency order
	sudo ~/pool-start.sh chain           # only lbcd + lbcwallet
	sudo ~/pool-start.sh stratum web     # individual components
	sudo tmux ls                         # list sessions
	sudo tmux attach -t lbcd             # watch a process (detach: Ctrl-b d)
	sudo ~/pool-stop.sh                  # graceful stop of everything (lbcd last)
	sudo ~/pool-stop.sh stratum          # stop one component

Components: `all`, `chain`, `lbcd`, `lbcwallet`, `stratum`, `blocknotify`, `web`, `debug`.
`pool-stop.sh` sends Ctrl-C and waits; lbcd (up to 10 min) and lbcwallet are
never force-killed, to avoid database corruption.

At the end of the install only lbcd and lbcwallet are running (needed for the
pool wallet address). Start the rest with `sudo ~/pool-start.sh` when ready.

After installing:
- Summary and credentials: `~/pool-credentials.txt`
- Wallet seed: `~/lbcwallet-seed.txt` - back it up offline, then delete the file
- Chain sync progress: `lbcctl getblockchaininfo` (stratum serves jobs once lbcd is synced)
- Wallet: `lbcctl --wallet getbalance`

## Database migrations

Existing pools must apply the migrations in `sql/` that are newer than their
schema, in date order, e.g.:

	mysql --defaults-group-suffix=host1 < sql/2026-11-04-lbc_stratum_widths.sql
	mysql --defaults-group-suffix=host1 < sql/2026-11-15-lbc_seed.sql

The stratum server checks the schema at startup and refuses to start (with a
message naming the migration) if tables/columns are missing or too narrow for
Bech32 (`lbc1...`) miner addresses.

## Admin access

On the website, go to http://server.com/site/ADMIN_PANEL (the path chosen during
install) to log in as admin; access is limited to the IPs entered during install
(`YAAMP_ADMIN_IP` in `/var/web/serverconfig.php`). You can add password
authentication in Nginx as well:

	sudo apt install apache2-utils
	sudo htpasswd -c /etc/nginx/admin.htpasswd <adminuser>

and in the site config (`/etc/nginx/sites-available/<server>.conf`):

	location ^~ /site/ADMIN_PANEL {
	        auth_basic "Yiimp Administration";
	        auth_basic_user_file /etc/nginx/admin.htpasswd;
	        try_files $uri /index.php?$args;
	}

## Logs

- Stratum: `/var/stratum/config/stratum.log`, `lbry.log`, `client.log`, `reject.log`
- Web backend: `/var/log/yiimp/debug.log`
- lbcd / lbcwallet: `/var/lib/lbc/.lbcd/logs`, `/var/lib/lbc/.lbcwallet/logs`
- Live output of any process: `sudo tmux attach -t <session>`

More instructions coming as needed.


Credits:

Thanks to globalzon to have released the initial Yaamp source code.
Thanks to tpruvot for updating the source code to yiimp.
Thanks to oakey22 for customising this for Lbry.
Thanks to Coolguy3289 for picking this project back up and getting the software compatible with lbrycrd again.
