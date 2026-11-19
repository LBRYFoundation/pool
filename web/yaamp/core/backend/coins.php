<?php

function percent_feedback($v, $n, $p)
{
	return ($v*(100-$p) + $n*$p) / 100;
}

function string_to_hashrate($s)
{
	$value = floatval(trim(preg_replace('/,/', '', $s)));

	if(stripos($s, 'kh/s')) $value *= 1000;
	if(stripos($s, 'mh/s')) $value *= 1000000;
	if(stripos($s, 'gh/s')) $value *= 1000000000;

	return $value;
}

/////////////////////////////////////////////////////////////////////////////////////////////

function BackendCoinsUpdate()
{
	$debug = false;

//	debuglog(__FUNCTION__);
	$t1 = microtime(true);

	$pool_rate = array();
	foreach(yaamp_get_algos() as $algo)
		$pool_rate[$algo] = yaamp_pool_rate($algo);

	$coins = getdbolist('db_coins', "installed");
	foreach($coins as $coin)
	{
//		debuglog("doing $coin->name");

		$remote = new WalletRPC($coin);

		$info = $remote->getinfo();
		if(!$info && $coin->enable)
		{
			debuglog("{$coin->symbol} no getinfo answer, retrying...");
			sleep(3);
			$info = $remote->getinfo();
			if (!$info) {
				debuglog("{$coin->symbol} disabled, no answer after 2 attempts. {$remote->error}");
				$coin->enable = false;
				$coin->connections = 0;
				$coin->save();
				continue;
			}
		}

		// auto-enable if auto_ready is set
		if($coin->auto_ready && !empty($info))
			$coin->enable = true;
		else if (empty($info))
			continue;

		if ($debug) echo "{$coin->symbol}\n";

		if(isset($info['difficulty']))
			$difficulty = $info['difficulty'];
		else
			$difficulty = $remote->getdifficulty();

		if(is_array($difficulty)) {
			$coin->difficulty = arraySafeVal($difficulty,'proof-of-work');
			$coin->difficulty_pos = arraySafeVal($difficulty,'proof-of-stake');
		}
		else
			$coin->difficulty = $difficulty;

		if($coin->algo == 'quark')
			$coin->difficulty /= 0x100;

		if($coin->difficulty == 0)
			$coin->difficulty = 1;

		$coin->errors = isset($info['errors'])? $info['errors']: '';
		$coin->txfee = isset($info['paytxfee'])? $info['paytxfee']: '';
		$coin->connections = isset($info['connections'])? $info['connections']: '';
		$coin->multialgos = (int) isset($info['pow_algo_id']);
		$coin->balance = isset($info['balance'])? $info['balance']: 0;
		$coin->stake = isset($info['stake'])? $info['stake'] : $coin->stake;
		$coin->mint = dboscalar("select sum(amount) from blocks where coin_id=$coin->id and category='immature'");

		if(empty($coin->master_wallet))
		{
			if (($coin->rpcencoding == 'DCR' || $coin->rpcencoding == 'LBC' || $coin->symbol == 'LBC') && empty($coin->account))
				$coin->account = 'default';
			$coin->master_wallet = $remote->getaccountaddress($coin->account);
		}

		if(empty($coin->rpcencoding))
		{
			if ($coin->symbol == 'LBC')
				$coin->rpcencoding = 'LBC';
			else
				$coin->rpcencoding = 'POW';
		}

		if($coin->hassubmitblock == NULL)
		{
			$remote->submitblock('');
			if(strcasecmp($remote->error, 'method not found') == 0)
				$coin->hassubmitblock = false;
			else
				$coin->hassubmitblock = true;
		}

		if($coin->auxpow == NULL)
			$coin->auxpow = false;

		$template = $remote->getblocktemplate('{}');

		if($template && isset($template['coinbasevalue']))
		{
			$coin->reward = $template['coinbasevalue']/100000000*$coin->reward_mul;

			if(isset($template['payee_amount']) && $coin->symbol != 'LIMX') {
				$coin->charity_amount = doubleval($template['payee_amount'])/100000000;
				$coin->reward -= $coin->charity_amount;
			}
			else if(!empty($coin->charity_address)) {
				if(!$coin->charity_amount)
					$coin->reward -= $coin->reward * $coin->charity_percent / 100;
			}

			if(isset($template['bits']))
			{
				$target = decode_compact($template['bits']);
				$coin->difficulty = target_to_diff($target);
			}
		}
		else if ($coin->rpcencoding == 'LBC' || $coin->symbol == 'LBC')
		{
			// Keep LBC auto_ready across transient lbcd/lbcwallet sync states
			if ($coin->connections > 0)
				$coin->auto_ready = true;
			$coin->errors = $remote->error;
		}
		else
		{
			$coin->auto_ready = false;
			$coin->errors = $remote->error;
		}

		if($coin->block_height != $info['blocks'])
		{
			$count = $info['blocks'] - $coin->block_height;
			$ttf = $count > 0 ? (time() - $coin->last_network_found) / $count : 0;

			if(empty($coin->actual_ttf)) $coin->actual_ttf = $ttf;

			$coin->actual_ttf = percent_feedback($coin->actual_ttf, $ttf, 5);
			$coin->last_network_found = time();
		}

		$coin->version = substr($info['version'], 0, 32);
		$coin->block_height = $info['blocks'];

		if($coin->powend_height > 0 && $coin->block_height > $coin->powend_height) {
			if ($coin->auto_ready) {
				$coin->auto_ready = false;
				$coin->errors = 'PoW end reached';
			}
		}

		$coin->save();

		if ($coin->available < 0 || $coin->cleared > $coin->balance) {
			// can happen after a payout (waiting first confirmation)
			BackendUpdatePoolBalances($coin->id);
		}
	//	debuglog(" end $coin->name");

	}

	$coins = getdbolist('db_coins', "enable order by auxpow desc");
	foreach($coins as $coin)
	{
		$coin = getdbo('db_coins', $coin->id);
		if(!$coin) continue;

		if($coin->difficulty)
		{
			$coin->index_avg = $coin->reward * $coin->price * 10000 / $coin->difficulty;
			if(!$coin->auxpow && $coin->rpcencoding == 'POW')
			{
				$indexaux = dboscalar("SELECT SUM(index_avg) FROM coins WHERE enable AND visible AND auto_ready AND auxpow AND algo='{$coin->algo}'");
				$coin->index_avg += $indexaux;
			}
		}

		if($coin->network_hash) {
			$coin->network_ttf = intval($coin->difficulty * 0x100000000 / $coin->network_hash);
			if($coin->network_ttf > 2147483647) $coin->network_ttf = 2147483647;
		}

		if(isset($pool_rate[$coin->algo]))
			$coin->pool_ttf = intval($coin->difficulty * 0x100000000 / $pool_rate[$coin->algo]);
		if($coin->pool_ttf > 2147483647) $coin->pool_ttf = 2147483647;

		if(strstr($coin->image, 'http'))
		{
			$data = file_get_contents($coin->image);
			$coin->image = "/images/coin-$coin->id.png";

			@unlink(YAAMP_HTDOCS.$coin->image);
			file_put_contents(YAAMP_HTDOCS.$coin->image, $data);
		}

		$coin->save();
	}

	$d1 = microtime(true) - $t1;
	controller()->memcache->add_monitoring_function(__METHOD__, $d1);
}




