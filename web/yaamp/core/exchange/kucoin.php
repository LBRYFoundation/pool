<?php

// see https://docs.kucoin.com/

function kucoin_result_valid($obj, $method='')
{
	if (!is_object($obj) || !isset($obj->data)) return false;
	return true;
}

// https://openapi-v2.kucoin.com/api/v1/symbols?market=BTC
// https://openapi-v2.kucoin.com/api/v1/currencies for labels

function kucoin_api_query($method, $params='', $returnType='object')
{
	$exchange = 'kucoin';
	$url = "https://openapi-v2.kucoin.com/api/v1/$method";
	if (!empty($params)) $url .= "?$params";

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/4.0 (compatible; KuCoin API PHP client; '.php_uname('s').'; PHP/'.phpversion().')');
	curl_setopt($ch, CURLOPT_ENCODING , '');
	//curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

	$res = curl_exec($ch);
	if($res === false) {
		$e = curl_error($ch);
		debuglog("$exchange: $method $e");
		curl_close($ch);
		return false;
	}

	if ($returnType == 'object')
		$ret = json_decode($res);
	else
		$ret = json_decode($res,true);

	if(!is_object($ret) && !is_array($ret)) {
		$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		debuglog("$exchange: $method failed ($status) ".strip_data($res));
	}
	curl_close($ch);
	return $ret;
}

// https://openapi-v2.kucoin.com/api/v1/deposit-addresses?currency=<coin>

function kucoin_api_user($method, $params=NULL, $isPostMethod=false)
{
	$exchange = 'kucoin';
	require_once('/etc/yiimp/keys.php');
	if (!defined('EXCH_KUCOIN_SECRET')) define('EXCH_KUCOIN_SECRET', '');

	if (empty(EXCH_KUCOIN_KEY) || empty(EXCH_KUCOIN_SECRET)) return false;
	if (empty(EXCH_KUCOIN_PASSPHRASE)) return false;

	$api_host = 'https://openapi-v2.kucoin.com';
	$mt = explode(' ', microtime());
	$nonce = $mt[1].substr($mt[0], 2, 3);
	$url = $endpoint = "/api/v1/$method";

	if (empty($params)) $params = array();
	$query = http_build_query($params);
	$body = "";
	if ($isPostMethod)
		$body = json_encode($params);
	else if (strlen($query)) {
		$body = '?'.$query;
		$url .= $body;
	}

	$req = $isPostMethod ? "POST" : "GET";
	$tosign = "{$nonce}{$req}{$endpoint}{$body}";
	$hmac = hash_hmac('sha256', $tosign, EXCH_KUCOIN_SECRET, true);

	$headers = array(
		'Content-Type: application/json;charset=UTF-8',
		'KC-API-KEY: '.EXCH_KUCOIN_KEY,
		'KC-API-PASSPHRASE: '.EXCH_KUCOIN_PASSPHRASE,
		'KC-API-TIMESTAMP: '.$nonce,
		'KC-API-SIGN: '.base64_encode($hmac),
	);

	$ch = curl_init();

	curl_setopt($ch, CURLOPT_URL, $api_host.$url);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	if ($isPostMethod) {
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
	}
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/4.0 (compatible; KuCoin API PHP client; '.php_uname('s').'; PHP/'.phpversion().')');
	curl_setopt($ch, CURLOPT_ENCODING , '');
	//curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	//curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	//curl_setopt($ch, CURLOPT_VERBOSE, 1);

	$res = curl_exec($ch);
	if($res === false) {
		$e = curl_error($ch);
		debuglog("$exchange: $method $e");
		curl_close($ch);
		return false;
	}

	$result = json_decode($res);
	if(!is_object($result) && !is_array($result)) {
		$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		debuglog("$exchange: $method failed ($status) ".strip_data($res));
	}

	curl_close($ch);

	return $result;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// manual update of one market
function kucoin_update_market($market)
{
	$exchange = 'kucoin';
	if (is_string($market))
	{
		$symbol = $market;
		$coin = getdbosql('db_coins', "symbol=:sym", array(':sym'=>$symbol));
		if(!$coin) return false;
		$pair = $symbol.'-BTC';
		$market = getdbosql('db_markets', "coinid={$coin->id} AND name='$exchange'");
		if(!$market) return false;

	} else if (is_object($market)) {

		$coin = getdbo('db_coins', $market->coinid);
		if(!$coin) return false;
		$symbol = $coin->getOfficialSymbol();
		$pair = $symbol.'-BTC';
		if (!empty($market->base_coin)) $pair = $symbol.'-'.$market->base_coin;
	}

	$t1 = microtime(true);
	$query = kucoin_api_query('market/orderbook/level1','symbol='.$pair);
	if(!kucoin_result_valid($query)) return false;
	$ticker = $query->data;

	$price2 = ((double) $ticker->bestBid + (double)$ticker->bestAsk)/2;
	$market->price2 = AverageIncrement($market->price2, $price2);
	$market->price = AverageIncrement($market->price, $ticker->bestBid);
	$market->pricetime = min(time(), 0 + $ticker->sequence);
	$market->save();

	$apims = round((microtime(true) - $t1)*1000,3);
	user()->setFlash('message', "$exchange $symbol price updated in $apims ms");

	return true;
}
