# LBRY Pool

A mining pool for [LBRY Credits (LBC)](https://lbry.com), based on [Yiimp](https://github.com/tpruvot/yiimp).
This is the codebase behind [LBRYPool](https://lbrypool.net).

> **Use at your own risk.** This is a fork of long-unmaintained software. Review the
> code and the install script before running them on a server that holds funds.

## Components

| Path | Description |
| --- | --- |
| `web/` | PHP (Yii 1) front end and admin panel, plus the backend loops (`main.sh`, `loop2.sh`, `blocks.sh`) |
| `stratum/` | C++ stratum server (LBRY algorithm only) |
| `blocknotify/` | Small client that tells the stratum a new block was found (run by `lbrycrdd`) |
| `sql/` | Database schema and migrations |
| `install.sh` | Automated installer for a fresh server |

## Requirements

- Ubuntu 18.04 or newer. The installer is only tested on 18.04, which is end-of-life.
- PHP 7.4. PHP 8.x is not supported yet (see the open issues).
- A dedicated server or VPS. Run the installer as a non-root user with `sudo` rights.

## Installation

1. Log in to your server and create a user with sudo rights:

   ```sh
   sudo adduser <username>
   sudo adduser <username> sudo
   sudo su - <username>
   ```

2. Download and run the installer, then follow the prompts:

   ```sh
   wget https://raw.githubusercontent.com/LBRYFoundation/pool/next/install.sh
   chmod +x install.sh
   ./install.sh
   ```

   The installer installs all dependencies (nginx, MariaDB, PHP, `lbrycrdd`), builds the
   stratum and blocknotify, creates the database, and generates `serverconfig.php` and
   the stratum config. It writes a log to `install.log` and saves your answers to
   `install.conf` (which is gitignored).

3. Start the pool:

   ```sh
   sudo bash ~/pool-start.sh
   ```

   This starts these tmux sessions: `main`, `loop2`, `blocks`, `debug` and `stratum`.
   Attach with `tmux attach -t <name>`.

Sample configuration files are in `web/serverconfig.sample.php`, `web/keys.sample.php`
and `stratum/config.sample/lbry.conf`.

## Configure the LBC coin

Open `http://<your-server>/site/<ADMIN_PANEL>` (the admin path you chose during
install), go to **Coins**, and edit **LBRY Credits (LBC)**:

| Field | Value |
| --- | --- |
| Algo | `lbry` |
| Image | `/images/coin-LBRY.png` |
| Process name | `lbrycrdd` |
| Conf. folder | `.lbrycrd` |
| RPC host | `127.0.0.1` |
| RPC user / password | The values printed at the end of the install |
| RPC type | `POW` |

Then tick **Enable**, **Auto Ready**, **Visible** and **Installed**, and save.

Restart the daemon so it picks up the change:

```sh
lbrycrd-cli stop
lbrycrdd -daemon
```

Other coins from the original Yiimp database may be listed. Untick **Installed** for
any coin you do not run.

## Admin access

The admin panel is restricted by IP address and by a secret URL path (set during
install, see `web/yaamp/modules/site/SiteController.php`). For stronger protection,
add HTTP basic auth in front of it. Example for nginx:

```sh
sudo htpasswd -c /etc/yiimp/admin.htpasswd <adminuser>
```

```nginx
location ~ ^/site/<ADMIN_PANEL> {
    auth_basic           "Pool Administration";
    auth_basic_user_file /etc/yiimp/admin.htpasswd;
    # ... your usual PHP/fastcgi settings ...
}
```

## Logs

- Stratum: `/var/stratum/` (and `/var/stratum/config/*.log`)
- PHP / web: `/var/log/stratum/debug.log`

## Credits

- globalzon, for the original Yaamp source.
- tpruvot, for updating it to Yiimp.
- oakey22, for customising it for LBRY.
- Coolguy3289, for bringing it back up to date with lbrycrd.
