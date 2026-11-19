<?php
/**
 * LBRY (lbcd / lbcwallet) & Bitcoin-compatible Wallet RPC wrapper
 */
class WalletRPC {

	public $type = 'Bitcoin';
	protected $rpc;
	protected $rpc_wallet;
	protected $hasGetInfo = false;

	// cache
	protected $account;
	protected $accounts;
	protected $coin;
	protected $info;
	protected $height = 0;

	// Information and debugging
	public $error;

	function __construct($userOrCoin, $pw='', $host='localhost', $port=9244, $url=null)
	{
		if (is_object($userOrCoin)) {
			$coin = $userOrCoin;
			$this->type = 'Bitcoin';
			$this->coin = $coin;
			$this->account = !empty($coin->account) ? $coin->account : 'default';
			$this->rpc = new Bitcoin($coin->rpcuser, $coin->rpcpasswd, $coin->rpchost, $coin->rpcport, $url);
			$this->hasGetInfo = $coin->hasgetinfo;

			if (($coin->rpcencoding == 'LBC' || $coin->symbol == 'LBC') && defined('LBC_DAEMON_PORT') && intval(LBC_DAEMON_PORT) > 0 && intval(LBC_DAEMON_PORT) != intval($coin->rpcport)) {
				$daemon_host = defined('LBC_DAEMON_HOST') ? LBC_DAEMON_HOST : $coin->rpchost;
				$this->rpc_wallet = new Bitcoin($coin->rpcuser, $coin->rpcpasswd, $daemon_host, intval(LBC_DAEMON_PORT), $url);
				if (defined('LBC_DAEMON_SSL') && LBC_DAEMON_SSL) {
					$cert = defined('LBC_DAEMON_CERT') && strlen(LBC_DAEMON_CERT) ? LBC_DAEMON_CERT : null;
					$this->rpc_wallet->setSSL($cert);
				}
			}
		} else {
			// backward compat
			$user = $userOrCoin;
			$this->rpc = new Bitcoin($user, $pw, $host, $port, $url);
		}
	}

	function __call($method, $params)
	{
		if (stripos($method, "dump") !== false || stripos($method, "backupwallet") !== false) {
			$this->error = "$method not authorized!";
			debuglog("$method rpc method is not authorized!");
			return false;
		}

		// lbcwallet requires a non-empty account name (usually "default") for account-based RPCs
		if (isset($this->coin) && ($this->coin->rpcencoding == 'LBC' || $this->coin->symbol == 'LBC')) {
			if (in_array($method, array('getaccountaddress', 'getaddressesbyaccount', 'getnewaddress')) && (empty($params) || $params[0] === '')) {
				$params[0] = !empty($this->coin->account) ? $this->coin->account : 'default';
			} elseif ($method == 'sendmany' && isset($params[0]) && $params[0] === '') {
				$params[0] = !empty($this->coin->account) ? $this->coin->account : 'default';
			} elseif ($method == 'listtransactions' && (empty($params) || $params[0] === '')) {
				$params[0] = '*';
			}
		}

		switch ($method) {
			case 'getinfo':
				if ($this->hasGetInfo) {
					$res = $this->rpc->__call($method, $params);
				} else {
					$miningInfo = $this->rpc->getmininginfo();
					$res["blocks"] = arraySafeVal($miningInfo, "blocks");
					$res["difficulty"] = arraySafeVal($miningInfo, "difficulty");
					$res["testnet"] = "main" != arraySafeVal($miningInfo, "chain");
					$walletInfo = $this->rpc->getwalletinfo();
					$res["walletversion"] = arraySafeVal($walletInfo, "walletversion");
					$res["balance"] = arraySafeVal($walletInfo, "balance");
					$res["keypoololdest"] = arraySafeVal($walletInfo, "keypoololdest");
					$res["keypoolsize"] = arraySafeVal($walletInfo, "keypoolsize");
					$res["paytxfee"] = arraySafeVal($walletInfo, "paytxfee");
					$networkInfo = $this->rpc->getnetworkinfo();
					$res["version"] = arraySafeVal($networkInfo, "version");
					$res["protocolversion"] = arraySafeVal($networkInfo, "protocolversion");
					$res["timeoffset"] = arraySafeVal($networkInfo, "timeoffset");
					$res["connections"] = arraySafeVal($networkInfo, "connections");
					$res["relayfee"] = arraySafeVal($networkInfo, "relayfee");
				}
				break;
			default:
				$res = $this->rpc->__call($method, $params);
				if ($res === false && isset($this->rpc_wallet) && stripos((string)$this->rpc->error, 'method not found') !== false) {
					$res = $this->rpc_wallet->__call($method, $params);
					$this->error = $this->rpc_wallet->error;
					return $res;
				}
		}

		$this->error = $this->rpc->error;
		return $res;
	}

	function __get($prop)
	{
		return $this->rpc->$prop;
	}

	function __set($prop, $value)
	{
		$this->rpc->$prop = $value;
	}

	function execute($query)
	{
		$result = '';

		if (!empty($query)) try {

			// if its a raw json query...
			if (strpos($query, "{") !== false && json_decode($query)) {
				try {
					debuglog($query);
					$result = $this->rpc->request_json($query);
					if ($result === false && isset($this->rpc_wallet) && stripos((string)$this->rpc->error, 'method not found') !== false) {
						$result = $this->rpc_wallet->request_json($query);
						$this->error = $this->rpc_wallet->error;
					}
				} catch (Exception $e) {
					$result = false;
				}
				return $result;
			}

			$params = explode(' ', trim($query));
			$command = array_shift($params);

			$p = array();
			foreach ($params as $param) {
				if ($param === 'true' || $param === 'false') {
					$param = $param === 'true' ? true : false;
				}
				else if (strpos($param, '0x') === 0)
					$param = "$param";
				else
					$param = (is_numeric($param)) ? 0 + $param : trim($param, '"');
				$p[] = $param;
			}

			switch (count($params)) {
			case 0:
				$result = $this->$command();
				break;
			case 1:
				$result = $this->$command($p[0]);
				break;
			case 2:
				$result = $this->$command($p[0], $p[1]);
				break;
			case 3:
				$result = $this->$command($p[0], $p[1], $p[2]);
				break;
			case 4:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3]);
				break;
			case 5:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4]);
				break;
			case 6:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5]);
				break;
			case 7:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5], $p[6]);
				break;
			case 8:
				$result = $this->$command($p[0], $p[1], $p[2], $p[3], $p[4], $p[5], $p[6], $p[7]);
				break;
			default:
				$result = 'error: too much parameters';
			}

		} catch (Exception $e) {
			$result = false;
		}

		return $result;
	}

}
