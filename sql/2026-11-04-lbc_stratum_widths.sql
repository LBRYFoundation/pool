-- Recent additions to add after db init (.gz)
-- mysql yaamp -p < file.sql

-- LBRY stratum: widen address/identity columns so Bech32 (lbc1...) miner
-- addresses and IPv6 client addresses fit. MariaDB >= 10.2 uses strict mode by
-- default, so values that are too long make INSERTs fail instead of being
-- silently truncated (a truncated address would be a wrong payout address).
-- Bech32 lbc1... addresses are 43 (P2WPKH) to 63 (P2WSH/P2TR) characters.
-- Safe to re-run.

-- stores the miner wallet address (was varchar(40))
ALTER TABLE workers MODIFY `name` varchar(128) DEFAULT NULL;

-- IPv6 textual form is up to 45 characters (was varchar(32))
ALTER TABLE workers MODIFY `ip` varchar(45) DEFAULT NULL;

-- (was varchar(39))
ALTER TABLE accounts MODIFY `hostaddr` varchar(45) DEFAULT NULL;

-- already widened by 2017-05-accounts_case_swaptime.sql, restated for older installs
ALTER TABLE accounts MODIFY `username` varchar(128) binary NOT NULL;
