<?php

// Functions commonly used in admin pages

function getAdminSideBarLinks()
{
$links = <<<end
<a href="/site/botnets">Botnets</a>&nbsp;
<a href="/site/user">Users</a>&nbsp;
<a href="/site/worker">Workers</a>&nbsp;
<a href="/site/version">Version</a>&nbsp;
<a href="/site/earning">Earnings</a>&nbsp;
<a href="/site/payments">Payments</a>&nbsp;
<a href="/site/monsters">Big Miners</a>&nbsp;
end;
	return $links;
}

// shared by wallet "tabs", to move in another php file...
function getAdminWalletLinks($coin, $info=NULL, $src='wallet')
{
	$html = CHtml::link("<b>COIN PROPERTIES</b>", '/site/update?id='.$coin->id);
	if($info) {
		$html .= ' || '.$coin->createExplorerLink("<b>EXPLORER</b>");
		$html .= ' || '.CHtml::link("<b>PEERS</b>", '/site/peers?id='.$coin->id);
		if (YAAMP_ADMIN_WEBCONSOLE)
			$html .= ' || '.CHtml::link("<b>CONSOLE</b>", '/site/console?id='.$coin->id);
		$html .= ' || '.CHtml::link("<b>TRIGGERS</b>", '/site/triggers?id='.$coin->id);
		if ($src != 'wallet')
			$html .= ' || '.CHtml::link("<b>{$coin->symbol}</b>", '/site/coin?id='.$coin->id);
	}

	if(!$info && $coin->enable)
		$html .= '<br/>'.CHtml::link("<b>STOP COIND</b>", '/site/stopcoin?id='.$coin->id);

	if($coin->auto_ready)
		$html .= '<br/>'.CHtml::link("<b>UNSET AUTO</b>", '/site/unsetauto?id='.$coin->id);
	else
		$html .= '<br/>'.CHtml::link("<b>SET AUTO</b>", '/site/setauto?id='.$coin->id);

	$html .= '<br/>';

	if(!empty($coin->link_bitcointalk))
		$html .= CHtml::link('forum', $coin->link_bitcointalk, array('target'=>'_blank')).' ';

	if(!empty($coin->link_github))
		$html .= CHtml::link('git', $coin->link_github, array('target'=>'_blank')).' ';

	if(!empty($coin->link_site))
		$html .= CHtml::link('site', $coin->link_site, array('target'=>'_blank')).' ';

	if(!empty($coin->link_explorer))
		$html .= CHtml::link('chain', $coin->link_explorer, array('target'=>'_blank','title'=>'External Blockchain Explorer')).' ';

	$html .= CHtml::link('google', 'http://google.com/search?q='.urlencode($coin->name.' '.$coin->symbol.' bitcointalk'), array('target'=>'_blank'));

	return $html;
}

/////////////////////////////////////////////////////////////////////////////////////////////

// Check if $IP is in $CIDR range
function ipCIDRCheck($IP, $CIDR)
{
	$parts = explode('/', $CIDR, 2);
	if (count($parts) !== 2) return false;
	list($net, $mask) = $parts;

	$mask = intval($mask);
	if ($mask < 0 || $mask > 32) return false;

	$ip_net = ip2long($net);
	$ip_ip = ip2long($IP);
	if ($ip_net === false || $ip_ip === false) return false;

	$ip_mask = $mask === 0 ? 0 : (~((1 << (32 - $mask)) - 1));
	return (($ip_ip & $ip_mask) === ($ip_net & $ip_mask));
}

function isAdminIP($ip)
{
	if (empty($ip) || !defined('YAAMP_ADMIN_IP') || trim(YAAMP_ADMIN_IP) === '')
		return false;

	foreach(explode(',', YAAMP_ADMIN_IP) as $range)
	{
		$range = trim($range);
		if ($range === '') continue;
		if (strpos($range, '/')) {
			if(ipCIDRCheck($ip, $range) === true) return true;
		} else if ($range === $ip) {
			return true;
		}
	}
	return false;
}

function getBestMarket($coin)
{
	return NULL;
}

function getMarketUrl($coin, $marketName)
{
	return '#';
}

/////////////////////////////////////////////////////////////////////////////////////////////
