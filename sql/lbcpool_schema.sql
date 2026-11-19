-- Consolidated LBRY (LBC) Mining Pool Schema & Seed Data
-- Includes all base tables and all schema migrations through 2026-11.
-- Compatible with MariaDB 10.6+ / MySQL 8.0+ in strict SQL mode.

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;

-- ---------------------------------------------------------------------------
-- Table `accounts`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `accounts` (
  `id` int(255) NOT NULL AUTO_INCREMENT,
  `coinid` int(11) DEFAULT NULL,
  `last_earning` int(10) DEFAULT NULL,
  `is_locked` tinyint(1) DEFAULT 0,
  `no_fees` tinyint(1) DEFAULT NULL,
  `donation` tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
  `logtraffic` tinyint(1) DEFAULT NULL,
  `balance` double DEFAULT 0,
  `username` varchar(128) binary NOT NULL,
  `coinsymbol` varchar(16) DEFAULT NULL,
  `swap_time` int(10) UNSIGNED DEFAULT NULL,
  `login` varchar(45) DEFAULT NULL,
  `hostaddr` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `coin` (`coinid`),
  KEY `balance` (`balance`),
  KEY `earning` (`last_earning`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `algos`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `algos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(16) DEFAULT NULL,
  `profit` double DEFAULT NULL,
  `rent` double DEFAULT NULL,
  `factor` double DEFAULT NULL,
  `overflow` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `balances`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `balances` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(16) DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `onsell` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `balanceuser`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `balanceuser` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `pending` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `userid` (`userid`),
  KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `bench_suffixes`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `bench_suffixes` (
  `vendorid` varchar(12) NOT NULL,
  `chip` varchar(32) DEFAULT NULL,
  `suffix` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`vendorid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `bench_chips`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `bench_chips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `devicetype` varchar(8) DEFAULT NULL,
  `vendorid` varchar(12) DEFAULT NULL,
  `chip` varchar(32) DEFAULT NULL,
  `year` int(4) UNSIGNED DEFAULT NULL,
  `maxtdp` double DEFAULT NULL,
  `blake_rate` double DEFAULT NULL,
  `blake_power` double DEFAULT NULL,
  `x11_rate` double DEFAULT NULL,
  `x11_power` double DEFAULT NULL,
  `sha_rate` double DEFAULT NULL,
  `sha_power` double DEFAULT NULL,
  `scrypt_rate` double DEFAULT NULL,
  `scrypt_power` double DEFAULT NULL,
  `dag_rate` double DEFAULT NULL,
  `dag_power` double DEFAULT NULL,
  `lyra_rate` double DEFAULT NULL,
  `lyra_power` double DEFAULT NULL,
  `neo_rate` double DEFAULT NULL,
  `neo_power` double DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `features` varchar(255) DEFAULT NULL,
  `perfdata` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ndx_chip_type` (`devicetype`),
  KEY `ndx_chip_name` (`chip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `benchmarks`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `benchmarks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `algo` varchar(16) NOT NULL,
  `type` varchar(8) NOT NULL,
  `khps` double DEFAULT NULL,
  `device` varchar(80) DEFAULT NULL,
  `vendorid` varchar(12) DEFAULT NULL,
  `chip` varchar(32) DEFAULT NULL,
  `idchip` int(11) DEFAULT NULL,
  `arch` varchar(8) DEFAULT NULL,
  `power` int(5) UNSIGNED DEFAULT NULL,
  `plimit` int(5) UNSIGNED DEFAULT NULL,
  `freq` int(8) UNSIGNED DEFAULT NULL,
  `realfreq` int(8) UNSIGNED DEFAULT NULL,
  `memf` int(8) UNSIGNED DEFAULT NULL,
  `realmemf` int(8) UNSIGNED DEFAULT NULL,
  `client` varchar(48) DEFAULT NULL,
  `os` varchar(8) DEFAULT NULL,
  `driver` varchar(32) DEFAULT NULL,
  `intensity` double DEFAULT NULL,
  `throughput` int(11) UNSIGNED DEFAULT NULL,
  `userid` int(11) DEFAULT NULL,
  `time` int(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  KEY `bench_userid` (`userid`),
  KEY `ndx_type` (`type`),
  KEY `ndx_algo` (`algo`),
  KEY `ndx_time` (`time`),
  KEY `ndx_chip` (`idchip`),
  CONSTRAINT `fk_bench_chip` FOREIGN KEY (`idchip`) REFERENCES `bench_chips` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `blocks`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `blocks` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `coin_id` int(11) DEFAULT NULL,
  `height` int(11) UNSIGNED DEFAULT NULL,
  `confirmations` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `userid` int(11) DEFAULT NULL,
  `workerid` int(11) DEFAULT NULL,
  `difficulty_user` double DEFAULT NULL,
  `price` double DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `difficulty` double DEFAULT NULL,
  `category` varchar(16) DEFAULT NULL,
  `algo` varchar(16) DEFAULT 'lbry',
  `blockhash` varchar(128) DEFAULT NULL,
  `txhash` varchar(128) DEFAULT NULL,
  `segwit` tinyint(1) UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `time` (`time`),
  KEY `algo1` (`algo`),
  KEY `coin` (`coin_id`),
  KEY `category` (`category`),
  KEY `user1` (`userid`),
  KEY `height1` (`height`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `coins`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `coins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) DEFAULT NULL,
  `symbol` varchar(16) DEFAULT NULL,
  `symbol2` varchar(16) DEFAULT NULL,
  `algo` varchar(16) DEFAULT NULL,
  `version` varchar(32) DEFAULT NULL,
  `image` varchar(1024) DEFAULT NULL,
  `market` varchar(64) DEFAULT NULL,
  `marketid` int(11) DEFAULT NULL,
  `master_wallet` varchar(1024) DEFAULT NULL,
  `charity_address` varchar(1024) DEFAULT NULL,
  `charity_amount` double DEFAULT NULL,
  `charity_percent` double DEFAULT NULL,
  `deposit_address` varchar(1024) DEFAULT NULL,
  `deposit_minimum` double DEFAULT 1,
  `sellonbid` tinyint(1) DEFAULT NULL,
  `dontsell` tinyint(1) DEFAULT 1,
  `block_explorer` varchar(1024) DEFAULT NULL,
  `index_avg` double DEFAULT NULL,
  `connections` int(11) DEFAULT NULL,
  `errors` varchar(1024) DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `immature` double DEFAULT NULL,
  `cleared` double DEFAULT NULL,
  `available` double DEFAULT NULL,
  `stake` double DEFAULT NULL,
  `mint` double DEFAULT NULL,
  `txfee` double DEFAULT NULL,
  `payout_min` double DEFAULT NULL,
  `payout_max` double DEFAULT NULL,
  `block_time` int(11) DEFAULT NULL,
  `difficulty` double DEFAULT 1,
  `difficulty_pos` double DEFAULT NULL,
  `block_height` int(11) DEFAULT NULL,
  `target_height` int(11) DEFAULT NULL,
  `powend_height` int(11) DEFAULT NULL,
  `network_hash` double DEFAULT NULL,
  `price` double DEFAULT NULL,
  `price2` double DEFAULT NULL,
  `reward` double DEFAULT 1,
  `reward_mul` double DEFAULT 1,
  `mature_blocks` int(11) DEFAULT NULL,
  `enable` tinyint(1) DEFAULT 0,
  `auto_ready` tinyint(1) DEFAULT 0,
  `visible` tinyint(1) DEFAULT NULL,
  `no_explorer` tinyint(1) UNSIGNED NOT NULL DEFAULT 0,
  `max_miners` int(11) DEFAULT NULL,
  `max_shares` int(11) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `action` int(11) DEFAULT NULL,
  `conf_folder` varchar(128) DEFAULT NULL,
  `program` varchar(128) DEFAULT NULL,
  `rpcuser` varchar(128) DEFAULT NULL,
  `rpcpasswd` varchar(128) DEFAULT NULL,
  `serveruser` varchar(45) DEFAULT NULL,
  `rpchost` varchar(128) DEFAULT NULL,
  `rpcport` int(11) DEFAULT NULL,
  `rpccurl` tinyint(1) NOT NULL DEFAULT 0,
  `rpcssl` tinyint(1) NOT NULL DEFAULT 0,
  `rpccert` varchar(255) DEFAULT NULL,
  `rpcencoding` varchar(16) DEFAULT NULL,
  `account` varchar(64) NOT NULL DEFAULT '',
  `hasgetinfo` tinyint(1) UNSIGNED NOT NULL DEFAULT 1,
  `hassubmitblock` tinyint(1) UNSIGNED NOT NULL DEFAULT 1,
  `hasmasternodes` tinyint(1) NOT NULL DEFAULT 0,
  `usememorypool` tinyint(1) DEFAULT NULL,
  `usesegwit` tinyint(1) UNSIGNED NOT NULL DEFAULT 0,
  `txmessage` tinyint(1) DEFAULT NULL,
  `auxpow` tinyint(1) DEFAULT NULL,
  `multialgos` tinyint(1) NOT NULL DEFAULT 0,
  `lastblock` varchar(128) DEFAULT NULL,
  `network_ttf` int(11) DEFAULT NULL,
  `actual_ttf` int(11) DEFAULT NULL,
  `pool_ttf` int(11) DEFAULT NULL,
  `last_network_found` int(11) DEFAULT NULL,
  `installed` tinyint(1) DEFAULT NULL,
  `watch` tinyint(1) NOT NULL DEFAULT 0,
  `link_site` varchar(1024) DEFAULT NULL,
  `link_exchange` varchar(1024) DEFAULT NULL,
  `link_bitcointalk` varchar(1024) DEFAULT NULL,
  `link_github` varchar(1024) DEFAULT NULL,
  `link_explorer` varchar(1024) DEFAULT NULL,
  `specifications` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `auto_ready` (`auto_ready`),
  KEY `enable` (`enable`),
  KEY `algo` (`algo`),
  KEY `symbol` (`symbol`),
  KEY `index_avg` (`index_avg`),
  KEY `created` (`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `bookmarks`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `bookmarks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `idcoin` int(11) NOT NULL,
  `label` varchar(32) DEFAULT NULL,
  `address` varchar(128) NOT NULL,
  `lastused` int(10) UNSIGNED DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `bookmarks_coin` (`idcoin`),
  CONSTRAINT `fk_bookmarks_coin` FOREIGN KEY (`idcoin`) REFERENCES `coins` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `connections`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `connections` (
  `id` int(11) NOT NULL,
  `user` varchar(64) DEFAULT NULL,
  `host` varchar(64) DEFAULT NULL,
  `db` varchar(64) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `idle` int(11) DEFAULT NULL,
  `last` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `earnings`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `earnings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) DEFAULT NULL,
  `coinid` int(11) DEFAULT NULL,
  `blockid` int(11) DEFAULT NULL,
  `create_time` int(11) DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `price` double DEFAULT NULL,
  `status` int(11) DEFAULT NULL,
  `mature_time` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ndx_user_block` (`userid`,`blockid`),
  KEY `user` (`userid`),
  KEY `coin` (`coinid`),
  KEY `block` (`blockid`),
  KEY `create1` (`create_time`),
  KEY `status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `exchange`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `exchange` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `coinid` int(11) DEFAULT NULL,
  `send_time` int(11) DEFAULT NULL,
  `receive_time` int(11) DEFAULT NULL,
  `price` double DEFAULT NULL,
  `price_estimate` double DEFAULT NULL,
  `quantity` double DEFAULT NULL,
  `fee` double DEFAULT NULL,
  `status` varchar(16) DEFAULT NULL,
  `market` varchar(16) DEFAULT NULL,
  `tx` varchar(65) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `coinid` (`coinid`),
  KEY `status` (`status`),
  KEY `market` (`market`),
  KEY `send_time` (`send_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `hashrate`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `hashrate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` int(11) DEFAULT NULL,
  `hashrate` bigint(11) DEFAULT NULL,
  `hashrate_bad` bigint(11) DEFAULT NULL,
  `price` double DEFAULT NULL,
  `rent` double DEFAULT NULL,
  `earnings` double DEFAULT NULL,
  `difficulty` double DEFAULT NULL,
  `algo` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `t1` (`time`),
  KEY `a1` (`algo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `hashrenter`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `hashrenter` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `renterid` int(11) DEFAULT NULL,
  `jobid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `hashrate` double DEFAULT NULL,
  `hashrate_bad` double DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `hashstats`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `hashstats` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` int(11) DEFAULT NULL,
  `hashrate` bigint(11) DEFAULT NULL,
  `earnings` double DEFAULT NULL,
  `algo` varchar(16) DEFAULT 'lbry',
  PRIMARY KEY (`id`),
  KEY `algo1` (`algo`),
  KEY `time1` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `hashuser`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `hashuser` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `hashrate` bigint(11) DEFAULT NULL,
  `hashrate_bad` bigint(11) DEFAULT NULL,
  `algo` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `u1` (`userid`),
  KEY `t1` (`time`),
  KEY `a1` (`algo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `jobs`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `renterid` int(11) DEFAULT NULL,
  `ready` tinyint(1) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `price` double DEFAULT NULL,
  `speed` double DEFAULT NULL,
  `difficulty` double DEFAULT NULL,
  `algo` varchar(16) DEFAULT NULL,
  `host` varchar(1024) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `username` varchar(1024) DEFAULT NULL,
  `password` varchar(1024) DEFAULT NULL,
  `percent` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `renterid` (`renterid`),
  KEY `ready` (`ready`),
  KEY `active` (`active`),
  KEY `algo` (`algo`),
  KEY `price` (`price`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `jobsubmits`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `jobsubmits` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `jobid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `valid` tinyint(1) DEFAULT NULL,
  `status` int(11) DEFAULT NULL,
  `difficulty` double DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `algo` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `markets`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `markets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `coinid` int(11) DEFAULT NULL,
  `disabled` tinyint(1) NOT NULL DEFAULT 0,
  `marketid` int(11) DEFAULT NULL,
  `priority` tinyint(1) NOT NULL DEFAULT 0,
  `lastsent` int(11) DEFAULT NULL,
  `lasttraded` int(11) DEFAULT 0,
  `balancetime` int(11) DEFAULT NULL,
  `deleted` tinyint(1) DEFAULT NULL,
  `txfee` double DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `ontrade` double NOT NULL DEFAULT 0,
  `price` double DEFAULT NULL,
  `price2` double DEFAULT NULL,
  `pricetime` int(11) DEFAULT NULL,
  `deposit_address` varchar(1024) DEFAULT NULL,
  `message` varchar(2048) DEFAULT NULL,
  `name` varchar(16) DEFAULT NULL,
  `base_coin` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `coinid` (`coinid`),
  KEY `name` (`name`),
  KEY `lastsent` (`lastsent`),
  KEY `lasttraded` (`lasttraded`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `market_history`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `market_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` int(11) NOT NULL,
  `idcoin` int(11) NOT NULL,
  `price` double DEFAULT NULL,
  `price2` double DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `idmarket` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idcoin` (`idcoin`),
  KEY `idmarket` (`idmarket`),
  KEY `time` (`time`),
  CONSTRAINT `fk_mh_market` FOREIGN KEY (`idmarket`) REFERENCES `markets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_mh_coin` FOREIGN KEY (`idcoin`) REFERENCES `coins` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `mining`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `mining` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `usdbtc` double DEFAULT NULL,
  `last_monitor_exchange` int(11) DEFAULT NULL,
  `last_update_price` int(11) DEFAULT NULL,
  `last_payout` int(11) DEFAULT NULL,
  `stratumids` varchar(1024) DEFAULT NULL,
  `best_algo` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `nicehash`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `nicehash` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) DEFAULT NULL,
  `orderid` int(11) DEFAULT NULL,
  `last_decrease` int(11) DEFAULT NULL,
  `algo` varchar(32) DEFAULT NULL,
  `btc` double DEFAULT NULL,
  `price` double DEFAULT NULL,
  `speed` double DEFAULT NULL,
  `workers` int(11) DEFAULT NULL,
  `accepted` double DEFAULT NULL,
  `rejected` double DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `notifications`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `idcoin` int(11) NOT NULL,
  `enabled` int(1) NOT NULL DEFAULT 0,
  `description` varchar(128) DEFAULT NULL,
  `conditiontype` varchar(32) DEFAULT NULL,
  `conditionvalue` double DEFAULT NULL,
  `notifytype` varchar(32) DEFAULT NULL,
  `notifycmd` varchar(512) DEFAULT NULL,
  `lastchecked` int(10) UNSIGNED DEFAULT NULL,
  `lasttriggered` int(10) UNSIGNED DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `notif_coin` (`idcoin`),
  KEY `notif_checked` (`lastchecked`),
  CONSTRAINT `fk_notif_coin` FOREIGN KEY (`idcoin`) REFERENCES `coins` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `orders`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `orders` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `coinid` int(11) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `price` double DEFAULT NULL,
  `ask` double DEFAULT NULL,
  `bid` double DEFAULT NULL,
  `market` varchar(16) DEFAULT NULL,
  `uuid` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `coinid` (`coinid`),
  KEY `created` (`created`),
  KEY `market` (`market`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `payouts`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `payouts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `idcoin` int(11) DEFAULT NULL,
  `time` int(11) NOT NULL,
  `completed` tinyint(1) NOT NULL DEFAULT 0,
  `amount` double DEFAULT NULL,
  `fee` double DEFAULT NULL,
  `tx` varchar(128) DEFAULT NULL,
  `memoid` varchar(128) DEFAULT NULL,
  `errmsg` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `account_id` (`account_id`,`completed`),
  KEY `payouts_coin` (`idcoin`),
  CONSTRAINT `fk_payouts_coin` FOREIGN KEY (`idcoin`) REFERENCES `coins` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_payouts_account` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `rawcoins`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rawcoins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) DEFAULT NULL,
  `symbol` varchar(32) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `renters`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `renters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  `address` varchar(1024) DEFAULT NULL,
  `email` varchar(1024) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL,
  `apikey` varbinary(1024) DEFAULT NULL,
  `received` double DEFAULT NULL,
  `balance` double DEFAULT NULL,
  `unconfirmed` double DEFAULT NULL,
  `spent` double DEFAULT NULL,
  `custom_start` double DEFAULT NULL,
  `custom_balance` double DEFAULT NULL,
  `custom_accept` double DEFAULT NULL,
  `custom_reject` double DEFAULT NULL,
  `custom_address` varchar(1024) DEFAULT NULL,
  `custom_server` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `rentertxs`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rentertxs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `renterid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `type` varchar(32) DEFAULT NULL,
  `address` varchar(1024) DEFAULT NULL,
  `tx` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `renterid` (`renterid`),
  KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `servers`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) DEFAULT NULL,
  `maxcoins` int(11) DEFAULT NULL,
  `uptime` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name1` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `services`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `services` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) DEFAULT NULL,
  `algo` varchar(64) DEFAULT NULL,
  `price` double DEFAULT NULL,
  `speed` bigint(20) DEFAULT NULL,
  `custom_balance` double DEFAULT NULL,
  `custom_accept` double DEFAULT NULL,
  `custom_reject` double DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `settings`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `settings` (
  `param` varchar(128) NOT NULL,
  `value` varchar(255) DEFAULT NULL,
  `type` varchar(8) DEFAULT NULL,
  PRIMARY KEY (`param`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `shares`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `shares` (
  `id` bigint(30) NOT NULL AUTO_INCREMENT,
  `userid` int(11) DEFAULT NULL,
  `workerid` int(11) DEFAULT NULL,
  `coinid` int(11) DEFAULT NULL,
  `jobid` int(11) DEFAULT NULL,
  `pid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `error` int(11) DEFAULT NULL,
  `valid` tinyint(1) DEFAULT NULL,
  `extranonce1` tinyint(1) DEFAULT NULL,
  `difficulty` double NOT NULL DEFAULT 0,
  `share_diff` double NOT NULL DEFAULT 0,
  `algo` varchar(16) DEFAULT 'lbry',
  PRIMARY KEY (`id`),
  KEY `time` (`time`),
  KEY `algo1` (`algo`),
  KEY `valid1` (`valid`),
  KEY `user1` (`userid`),
  KEY `worker1` (`workerid`),
  KEY `coin1` (`coinid`),
  KEY `jobid` (`jobid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `stats`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `stats` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` int(11) DEFAULT NULL,
  `profit` double DEFAULT NULL,
  `wallet` double DEFAULT NULL,
  `wallets` double DEFAULT NULL,
  `immature` double DEFAULT NULL,
  `margin` double DEFAULT NULL,
  `waiting` double DEFAULT NULL,
  `balances` double DEFAULT NULL,
  `onsell` double DEFAULT NULL,
  `renters` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `stratums`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `stratums` (
  `pid` int(11) NOT NULL,
  `time` int(11) DEFAULT NULL,
  `started` int(11) UNSIGNED DEFAULT NULL,
  `algo` varchar(64) DEFAULT NULL,
  `workers` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `port` int(6) UNSIGNED DEFAULT NULL,
  `symbol` varchar(16) DEFAULT NULL,
  `url` varchar(128) DEFAULT NULL,
  `fds` int(10) UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`pid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `withdraws`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `withdraws` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `market` varchar(1024) DEFAULT NULL,
  `address` varchar(1024) DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `uuid` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ---------------------------------------------------------------------------
-- Table `workers`
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `workers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) DEFAULT NULL,
  `time` int(11) DEFAULT NULL,
  `pid` int(11) DEFAULT NULL,
  `subscribe` tinyint(1) DEFAULT NULL,
  `difficulty` double DEFAULT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `dns` varchar(1024) DEFAULT NULL,
  `name` varchar(128) DEFAULT NULL,
  `nonce1` varchar(64) DEFAULT NULL,
  `version` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL,
  `worker` varchar(64) DEFAULT NULL,
  `algo` varchar(16) DEFAULT 'lbry',
  PRIMARY KEY (`id`),
  KEY `algo1` (`algo`),
  KEY `name1` (`name`),
  KEY `userid` (`userid`),
  KEY `pid` (`pid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

SET foreign_key_checks = 1;

-- ---------------------------------------------------------------------------
-- LBRY Pool Seed Data
-- ---------------------------------------------------------------------------
INSERT INTO `algos` (`name`, `profit`, `rent`, `factor`, `overflow`)
SELECT 'lbry', 0, 0, 1, 0 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM `algos` WHERE `name` = 'lbry');

INSERT INTO `mining` (`id`, `usdbtc`, `last_monitor_exchange`, `last_update_price`, `last_payout`, `stratumids`, `best_algo`)
SELECT 1, 0, 0, 0, UNIX_TIMESTAMP(), '', 'lbry' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM `mining`);
