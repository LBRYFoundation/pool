#include "stratum.h"

void coind_error(YAAMP_COIND *coind, const char *s)
{
	// Keep coind active across transient lbcd/lbcwallet RPC errors
	stratumlog("%s error %s\n", coind->name, s);
}

double coind_profitability(YAAMP_COIND *coind)
{
	if(!coind->difficulty) return 0;
	if(coind->pool_ttf > g_stratum_max_ttf) return 0;

	double prof = 20116.56761169 / coind->difficulty * coind->reward * coind->price;
	if(!strcmp(g_current_algo->name, "sha256")) prof *= 1000;

	return prof;
}

double coind_nethash(YAAMP_COIND *coind)
{
	double speed = coind->difficulty * 0x100000000 / 1000000 / max(min(coind->actual_ttf, 60), 30);
	return speed;
}

void coind_sort()
{
	bool swapped = true;
	while(swapped)
	{
		swapped = false;
		for(CLI li = g_list_coind.first; li && li->next; li = li->next)
		{
			YAAMP_COIND *coind1 = (YAAMP_COIND *)li->data;
			if(coind1->deleted) continue;

			YAAMP_COIND *coind2 = (YAAMP_COIND *)li->next->data;
			if(coind2->deleted) continue;

			double p1 = coind_profitability(coind1);
			double p2 = coind_profitability(coind2);

			if(p2 > p1)
			{
				g_list_coind.Swap(li, li->next);
				swapped = true;
			}
		}
	}
}

bool coind_can_mine(YAAMP_COIND *coind)
{
	if(coind->deleted) return false;
	if(!coind->enable) return false;
	if(!coind->auto_ready) return false;
	if(!rpc_connected(&coind->rpc)) return false;
	if(!coind->height) return false;
	if(!coind->difficulty) return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////

bool coind_validate_user_address(YAAMP_COIND *coind, char* const address)
{
	if(!address[0]) return false;

	char params[YAAMP_SMALLBUFSIZE];
	snprintf(params, sizeof(params), "[\"%s\"]", address);

	json_value *json = rpc_call(&coind->rpc, "validateaddress", params);
	if(!json) return false;

	json_value *json_result = json_get_object(json, "result");
	if(!json_result) {
		json_value_free(json);
		return false;
	}

	bool isvalid = json_get_bool(json_result, "isvalid");
	if(!isvalid) stratumlog("%s: %s user address %s is not valid.\n", g_stratum_algo, coind->symbol, address);

	json_value_free(json);

	return isvalid;
}

///////////////////////////////////////////////////////////////////////////////

bool coind_validate_address(YAAMP_COIND *coind)
{
	if(!coind->wallet[0]) return false;

	char params[YAAMP_SMALLBUFSIZE];
	snprintf(params, sizeof(params), "[\"%s\"]", coind->wallet);

	json_value *json = rpc_call(&coind->rpc, "validateaddress", params);
	if(!json) return false;

	json_value *json_result = json_get_object(json, "result");
	if(!json_result)
	{
		json_value_free(json);
		return false;
	}

	bool isvalid = json_get_bool(json_result, "isvalid");
	if(!isvalid) stratumlog("%s wallet %s is not valid.\n", coind->name, coind->wallet);

	bool ismine = json_get_bool(json_result, "ismine");
	if(!ismine) stratumlog("%s wallet %s is not mine.\n", coind->name, coind->wallet);
	else isvalid = ismine;

	const char *p = json_get_string(json_result, "pubkey");
	snprintf(coind->pubkey, sizeof(coind->pubkey), "%s", p ? p : "");

	const char *acc = json_get_string(json_result, "account");
	if (acc) snprintf(coind->account, sizeof(coind->account), "%s", acc);

	coind->p2sh_address = json_get_bool(json_result, "isscript");
	coind->raw_script_pubkey = false;
	memset(coind->script_pubkey, 0, sizeof(coind->script_pubkey));

	if (!base58_decode(coind->wallet, coind->script_pubkey))
		stratumlog("Warning: unable to base58 decode %s %s script pubkey\n", coind->symbol, coind->wallet);

	// Fallback when base58 decode did not produce a hash160 (e.g. Bech32 lbc1... pool wallet).
	// lbcd returns witness_version/witness_program, bitcoind-style nodes return scriptPubKey,
	// and lbcwallet may return neither.
	if (!strlen(coind->script_pubkey)) {
		const char *pk = json_get_string(json_result, "scriptPubKey");
		const char *wprog = json_get_string(json_result, "witness_program");
		json_value *wver = json_get_val(json_result, "witness_version");
		size_t wprog_len = wprog ? strlen(wprog) : 0;

		if (wprog && wver && wver->type == json_integer && wprog_len >= 4 && wprog_len <= 80 && !(wprog_len & 1)
			&& wver->u.integer >= 0 && wver->u.integer <= 16)
		{
			// Segwit scriptPubKey: OP_n <push len> <program>
			int ver = (int)wver->u.integer;
			unsigned int opver = ver ? (unsigned int)(0x50 + ver) : 0x00;
			snprintf(coind->script_pubkey, sizeof(coind->script_pubkey), "%02x%02x%s",
				opver, (unsigned int)(wprog_len >> 1), wprog);
			coind->raw_script_pubkey = true;
			coind->p2sh_address = false;
			stratumlog("%s %s built witness scriptPubKey %s\n", coind->symbol, coind->wallet, coind->script_pubkey);
		} else if (pk && strlen(pk) == 50 && strncmp(pk, "76a914", 6) == 0) {
			strncpy(coind->script_pubkey, pk + 6, 40);
			coind->script_pubkey[40] = '\0';
			stratumlog("%s %s extracted P2PKH hash160 is %s\n", coind->symbol, coind->wallet, coind->script_pubkey);
		} else if (pk && strlen(pk) >= 4 && strlen(pk) < sizeof(coind->script_pubkey)) {
			snprintf(coind->script_pubkey, sizeof(coind->script_pubkey), "%s", pk);
			coind->raw_script_pubkey = true;
			stratumlog("%s %s extracted raw scriptPubKey is %s\n", coind->symbol, coind->wallet, coind->script_pubkey);
		} else {
			stratumlog("ERROR: %s pool wallet '%s' script_pubkey could not be determined: validateaddress "
				"returned neither witness_version/witness_program nor scriptPubKey. "
				"Use a Base58 (b.../r...) pool wallet address instead.\n", coind->symbol, coind->wallet);
			isvalid = false;
		}
	}
	json_value_free(json);

	return isvalid && ismine;
}

void coind_init(YAAMP_COIND *coind)
{
	char params[YAAMP_SMALLBUFSIZE];
	char account[YAAMP_SMALLBUFSIZE];

	yaamp_create_mutex(&coind->mutex);

	snprintf(account, sizeof(account), "%s", coind->account);
	if(!strcmp(coind->rpcencoding, "LBC") && !strlen(account)) {
		snprintf(account, sizeof(account), "default");
	}

	bool valid = coind_validate_address(coind);
	if(valid) return;

	snprintf(params, sizeof(params), "[\"%s\"]", account);

	json_value *json = rpc_call(&coind->rpc, "getaccountaddress", params);
	if(!json)
	{
		json = rpc_call(&coind->rpc, "getaddressesbyaccount", params);
		if (json && json_is_array(json) && json->u.object.length) {
			debuglog("is array...");
			if (json->u.object.values[0].value->type == json_string)
				json = json->u.object.values[0].value;
		}
		if (!json) {
			stratumlog("ERROR getaccountaddress %s\n", coind->name);
			return;
		}
	}

	if (json->u.object.values[0].value->type == json_string) {
		snprintf(coind->wallet, sizeof(coind->wallet), "%s", json->u.object.values[0].value->u.string.ptr);
	}
	else {
		coind->wallet[0] = '\0';
		stratumlog("ERROR getaccountaddress %s\n", coind->name);
	}

	json_value_free(json);

	coind_validate_address(coind);
	if (strlen(coind->wallet)) {
		debuglog(">>>>>>>>>>>>>>>>>>>> using wallet %s %s\n",
			coind->wallet, coind->account);
	}
}

void coind_terminate(YAAMP_COIND *coind)
{
	debuglog("disconnecting from coind %s\n", coind->symbol);

	rpc_close(&coind->rpc);
#ifdef HAVE_CURL
	if (coind->rpc.curl) rpc_curl_close(&coind->rpc);
#endif

	pthread_mutex_unlock(&coind->mutex);
	pthread_mutex_destroy(&coind->mutex);

	object_delete(coind);
}
