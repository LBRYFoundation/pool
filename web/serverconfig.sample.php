<?php

ini_set('date.timezone', 'UTC');

define('YAAMP_LOGS', '/var/log');
define('YAAMP_HTDOCS', '/var/web');
define('YAAMP_BIN', '/var/bin');

define('YAAMP_DBHOST', 'localhost');
define('YAAMP_DBNAME', 'yaamp');
define('YAAMP_DBUSER', 'root');
define('YAAMP_DBPASSWORD', 'password');

define('YAAMP_PRODUCTION', true);
define('YAAMP_RENTAL', false);
define('YAAMP_LIMIT_ESTIMATE', false);

define('YAAMP_FEES_MINING', 0.5);
define('YAAMP_FEES_EXCHANGE', 2);
define('YAAMP_FEES_RENTING', 2);
define('YAAMP_TXFEE_RENTING_WD', 0.002);
define('YAAMP_PAYMENTS_FREQ', 3*60*60);
define('YAAMP_PAYMENTS_MINI', 0.001);

define('YAAMP_ALLOW_EXCHANGE', false);
define('YIIMP_PUBLIC_EXPLORER', true);
define('YIIMP_PUBLIC_BENCHMARK', false);
define('YIIMP_FIAT_ALTERNATIVE', 'EUR'); // USD is main

define('YAAMP_USE_NICEHASH_API', false);

define('YAAMP_BTCADDRESS', '1Auhps1mHZQpoX4mCcVL8odU81VakZQ6dR');
define('YAAMP_SITE_URL', 'yiimp.ccminer.org');
define('YAAMP_STRATUM_URL', YAAMP_SITE_URL); // change if your stratum server is on a different host
define('YAAMP_SITE_NAME', 'YiiMP');
define('YAAMP_ADMIN_EMAIL', 'yiimp@spam.la');
define('YAAMP_ADMIN_IP', ''); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
define('YAAMP_ADMIN_WEBCONSOLE', true);
define('YAAMP_NOTIFY_NEW_COINS', true);
define('YAAMP_DEFAULT_ALGO', 'lbry');
define('YAAMP_CREATE_NEW_COINS', false);


define('YAAMP_USE_NGINX', true);

define('LBC_DAEMON_HOST', '127.0.0.1');
define('LBC_DAEMON_PORT', 9245);
define('LBC_DAEMON_SSL', false);
define('LBC_DAEMON_CERT', '');

$cold_wallet_table = array();

// Sample fixed pool fees
$configFixedPoolFees = array(
//	'lbry' => 0.5,
);

// Sample custom stratum ports
$configCustomPorts = array(
//	'lbry' => 3334,
);

// mBTC Coefs per algo (default is 1.0)
$configAlgoNormCoef = array(
//	'lbry' => 1.0,
);

