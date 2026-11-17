#include "stratum.h"

YAAMP_JOB_TEMPLATE *coind_create_template_memorypool(YAAMP_COIND *coind)
{
	json_value *json = rpc_call(&coind->rpc, "getmemorypool");
	if(!json || json->type == json_null)
	{
		coind_error(coind, "getmemorypool");
		return NULL;
	}

	json_value *json_result = json_get_object(json, "result");
	if(!json_result || json_result->type == json_null)
	{
		coind_error(coind, "getmemorypool");
		json_value_free(json);

		return NULL;
	}

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE();

	templ->created = time(NULL);
	templ->value = json_get_int(json_result, "coinbasevalue");
	snprintf(templ->version, sizeof(templ->version), "%08x", (unsigned int)json_get_int(json_result, "version"));
	snprintf(templ->ntime, sizeof(templ->ntime), "%08x", (unsigned int)json_get_int(json_result, "time"));
	const char *bits = json_get_string(json_result, "bits");
	snprintf(templ->nbits, sizeof(templ->nbits), "%s", bits ? bits : "");
	const char *prev = json_get_string(json_result, "previousblockhash");
	snprintf(templ->prevhash_hex, sizeof(templ->prevhash_hex), "%s", prev ? prev : "");

	json_value_free(json);

	json = rpc_call(&coind->rpc, "getmininginfo", "[]");
	if(!json || json->type == json_null)
	{
		coind_error(coind, "coind getmininginfo");
		delete templ;
		return NULL;
	}

	json_result = json_get_object(json, "result");
	if(!json_result || json_result->type == json_null)
	{
		coind_error(coind, "coind getmininginfo");
		json_value_free(json);
		delete templ;
		return NULL;
	}

	templ->height = json_get_int(json_result, "blocks")+1;
	json_value_free(json);

	coind->usememorypool = true;
	return templ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

YAAMP_JOB_TEMPLATE *coind_create_template(YAAMP_COIND *coind)
{
	if(coind->usememorypool)
		return coind_create_template_memorypool(coind);

	char params[512] = "[{}]";
	if(g_stratum_segwit) strcpy(params, "[{\"rules\":[\"segwit\"]}]");

	json_value *json = rpc_call(&coind->rpc, "getblocktemplate", params);
	if(!json || json_is_null(json))
	{
		if (!strcmp(coind->rpcencoding, "LBC") || !strcmp(coind->symbol, "LBC")) {
			char curl_err[256] = { 0 };
			rpc_curl_get_lasterr(curl_err, sizeof(curl_err));
			debuglog("%s getblocktemplate failed (%s:%d%s%s)\n", coind->symbol,
				coind->rpc.host, coind->rpc.port, curl_err[0] ? ": " : "", curl_err);
		}
		else
			coind_error(coind, "getblocktemplate");
		return NULL;
	}

	json_value *json_result = json_get_object(json, "result");
	if(!json_result || json_is_null(json_result))
	{
		json_value *json_err = json_get_object(json, "error");
		const char *err_msg = json_err ? json_get_string(json_err, "message") : NULL;
		int err_code = json_err ? (int)json_get_int(json_err, "code") : 0;

		// If coins.rpcport was pointed at lbcwallet (e.g. 9244), lbcwallet returns -32601 Method not found
		// for getblocktemplate because mining RPCs are served by lbcd (default port 9245).
		if (err_code == -32601 && (!strcmp(coind->symbol, "LBC") || !strcmp(coind->rpcencoding, "LBC")) && coind->rpc.port != 9245) {
			if (!coind->rpc_wallet.port) {
				coind->rpc_wallet = coind->rpc;
				coind->rpc_wallet.CURL = NULL;
				coind->rpc_wallet.sock = 0;
				yaamp_create_mutex(&coind->rpc_wallet.mutex);
			}
			int old_port = coind->rpc.port;
			coind->rpc.port = 9245;
			coind->rpc.curl = 1;
			stratumlog("%s RPC on %s:%d returned '%s' for getblocktemplate (likely lbcwallet); "
				"switching mining RPC to lbcd on %s:%d and keeping wallet RPC on :%d\n",
				coind->symbol, coind->rpc.host, old_port, err_msg ? err_msg : "Method not found",
				coind->rpc.host, coind->rpc.port, old_port);
			json_value_free(json);
			json = rpc_call(&coind->rpc, "getblocktemplate", params);
			json_result = json ? json_get_object(json, "result") : NULL;
			if (!json || !json_result || json_is_null(json_result)) {
				json_err = json ? json_get_object(json, "error") : NULL;
				err_msg = json_err ? json_get_string(json_err, "message") : NULL;
				stratumlog("%s getblocktemplate result error on %s:%d: %s\n",
					coind->symbol, coind->rpc.host, coind->rpc.port, err_msg ? err_msg : "no result");
				if (json) json_value_free(json);
				return NULL;
			}
		} else {
			if (err_msg && err_msg[0])
				stratumlog("%s getblocktemplate error (%d): %s\n", coind->symbol, err_code, err_msg);
			else
				coind_error(coind, "getblocktemplate result");
			json_value_free(json);
			return NULL;
		}
	}

	// segwit rule
	json_value *json_rules = json_get_array(json_result, "rules");
	if(json_rules && !strlen(coind->witness_magic) && json_rules->u.array.length) {
		for (unsigned int i = 0; i < json_rules->u.array.length; i++) {
			json_value *val = json_rules->u.array.values[i];
			if(val->type == json_string && !strcmp(val->u.string.ptr, "segwit")) {
				const char *commitment = json_get_string(json_result, "default_witness_commitment");
				strcpy(coind->witness_magic, "aa21a9ed");
				if (commitment && strlen(commitment) > 12) {
					strncpy(coind->witness_magic, &commitment[4], 8);
					coind->witness_magic[8] = '\0';
				}
				coind->usesegwit |= g_stratum_segwit;
				if (coind->usesegwit)
					debuglog("%s segwit enabled, magic %s\n", coind->symbol, coind->witness_magic);
				break;
			}
		}
	}

	json_value *json_tx = json_get_array(json_result, "transactions");
	if(!json_tx)
	{
		coind_error(coind, "getblocktemplate transactions");
		json_value_free(json);
		return NULL;
	}

	json_value *json_coinbaseaux = json_get_object(json_result, "coinbaseaux");

	YAAMP_JOB_TEMPLATE *templ = new YAAMP_JOB_TEMPLATE();

	templ->created = time(NULL);
	templ->value = json_get_int(json_result, "coinbasevalue");
	templ->height = json_get_int(json_result, "height");
	snprintf(templ->version, sizeof(templ->version), "%08x", (unsigned int)json_get_int(json_result, "version"));
	snprintf(templ->ntime, sizeof(templ->ntime), "%08x", (unsigned int)json_get_int(json_result, "curtime"));

	const char *bits = json_get_string(json_result, "bits");
	snprintf(templ->nbits, sizeof(templ->nbits), "%s", bits ? bits : "");
	const char *prev = json_get_string(json_result, "previousblockhash");
	snprintf(templ->prevhash_hex, sizeof(templ->prevhash_hex), "%s", prev ? prev : "");
	const char *flags = json_coinbaseaux ? json_get_string(json_coinbaseaux, "flags") : NULL;
	snprintf(templ->flags, sizeof(templ->flags), "%s", flags ? flags : "");

	// LBC Claim Trie Root (lbcd returns "claimtrie" directly in getblocktemplate)
	const char *claim = json_get_string(json_result, "claimtrie");
	if (claim && strlen(claim) > 0) {
		snprintf(templ->claim_hex, sizeof(templ->claim_hex), "%s", claim);
	}
	else if (strcmp(coind->symbol, "LBC") == 0 || strcmp(coind->rpcencoding, "LBC") == 0) {
		json_value *json_claim = rpc_call(&coind->rpc, "getclaimtrie");
		if (json_claim && json_claim->type == json_object) {
			json_value *json_cls = json_get_array(json_claim, "result");
			if (json_cls && json_is_array(json_cls) && json_cls->u.array.length > 0) {
				json_value *json_obj = json_cls->u.array.values[0];
				if (json_obj && json_obj->type == json_object) {
					claim = json_get_string(json_obj, "hash");
					if (claim && strlen(claim) > 0) {
						snprintf(templ->claim_hex, sizeof(templ->claim_hex), "%s", claim);
					}
				}
			}
		}
		if (json_claim)
			json_value_free(json_claim);

		// Empty claimtrie root must be 0x01 in big-endian hex (per lbcd chaincfg)
		if (!strlen(templ->claim_hex)) {
			strcpy(templ->claim_hex, "0000000000000000000000000000000000000000000000000000000000000001");
		}
	}

	if (!templ->height || !strlen(templ->nbits) || !strlen(templ->prevhash_hex)) {
		stratumlog("%s warning, gbt incorrect : version=%s height=%d value=%lld bits=%s time=%s prev=%s\n",
			coind->symbol, templ->version, templ->height, (long long)templ->value, templ->nbits, templ->ntime, templ->prevhash_hex);
	}

	//////////////////////////////////////////////////////////////////////////////////////////

	vector<string> txhashes;
	vector<string> txids;
	txhashes.push_back("");
	txids.push_back("");

	templ->has_segwit_txs = false;
	templ->has_filtered_txs = false;
	templ->filtered_txs_fee = 0;

	for(unsigned int i = 0; i < json_tx->u.array.length; i++)
	{
		const char *p = json_get_string(json_tx->u.array.values[i], "hash");
		if (!p) p = json_get_string(json_tx->u.array.values[i], "txid");
		if (!p) continue;

		char hash_be[256] = { 0 };

		if (templ->has_filtered_txs) {
			templ->filtered_txs_fee += json_get_int(json_tx->u.array.values[i], "fee");
			continue;
		}

		string_be(p, hash_be);
		txhashes.push_back(hash_be);

		const char *txid = json_get_string(json_tx->u.array.values[i], "txid");
		if(txid && strlen(txid)) {
			char txid_be[256] = { 0 };
			string_be(txid, txid_be);
			txids.push_back(txid_be);
			if (strcmp(hash_be, txid_be)) {
				templ->has_segwit_txs = true;
			}
		} else {
			templ->has_segwit_txs = false;
		}

		const char *d = json_get_string(json_tx->u.array.values[i], "data");
		if (d) templ->txdata.push_back(d);

		if (g_limit_txs_per_block && (int)i >= g_limit_txs_per_block - 2) {
			debuglog("limiting block to %d first txs (of %d)\n", g_limit_txs_per_block, json_tx->u.array.length);
			templ->has_filtered_txs = true;
		}
	}

	if (templ->has_filtered_txs) {
		templ->value -= templ->filtered_txs_fee;
	}

	templ->txmerkles[0] = '\0';
	if(templ->has_segwit_txs) {
		templ->txcount = txids.size();
		templ->txsteps = merkle_steps(txids);
	} else {
		templ->txcount = txhashes.size();
		templ->txsteps = merkle_steps(txhashes);
	}

	if(templ->has_segwit_txs) {
		const char *commitment = json_get_string(json_result, "default_witness_commitment");
		if (commitment) {
			snprintf(coind->commitment, sizeof(coind->commitment), "%s", commitment);
		} else {
			templ->has_segwit_txs = false;
		}
	}

	txhashes.clear();
	txids.clear();

	vector<string>::const_iterator i;
	for(i = templ->txsteps.begin(); i != templ->txsteps.end(); ++i)
		sprintf(templ->txmerkles + strlen(templ->txmerkles), "\"%s\",", (*i).c_str());

	if(templ->txmerkles[0])
		templ->txmerkles[strlen(templ->txmerkles)-1] = 0;

	ser_string_be2(templ->prevhash_hex, templ->prevhash_be, 8);

	if(!strcmp(coind->symbol, "LBC") || !strcmp(coind->rpcencoding, "LBC") || strlen(templ->claim_hex) == 64)
		ser_string_be2(templ->claim_hex, templ->claim_be, 8);

	coinbase_create(coind, templ, json_result);
	json_value_free(json);

	return templ;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool coind_create_job(YAAMP_COIND *coind, bool force)
{
	bool b = rpc_connected(&coind->rpc);
	if(!b) return false;

	CommonLock(&coind->mutex);

	YAAMP_JOB_TEMPLATE *templ = coind_create_template(coind);
	if(!templ)
	{
		CommonUnlock(&coind->mutex);
		stratumlog("%s: create job template failed!\n", coind->symbol);
		return false;
	}

	stratumlog("templ->height: %d, coind->height: %d\n", templ->height, coind->height);

	YAAMP_JOB *job_last = coind->job;

	if(	!force && job_last && job_last->templ && job_last->templ->created + 45 > time(NULL) &&
		templ->height == job_last->templ->height &&
		templ->txcount == job_last->templ->txcount &&
		strcmp(templ->coinb2, job_last->templ->coinb2) == 0)
	{
		if (templ->txcount) {
			templ->txsteps.clear();
			templ->txdata.clear();
		}
		delete templ;

		CommonUnlock(&coind->mutex);
		return true;
	}

	////////////////////////////////////////////////////////////////////////////////////////

	int height = coind->height;
	coind->height = templ->height - 1;

	if(height > coind->height)
	{
		stratumlog("%s went from %d to %d\n", coind->name, height, coind->height);
	}

	if(height < coind->height && !coind->newblock)
	{
		if(coind->auto_ready && coind->notreportingcounter++ > 5)
			stratumlog("%s %d not reporting\n", coind->name, coind->height);
	}

	uint64_t coin_target = decode_compact(templ->nbits);
	if (templ->nbits[0] && !coin_target) coin_target = 0xFFFF000000000000ULL;
	coind->difficulty = target_to_diff(coin_target);

	coind->newblock = false;

	////////////////////////////////////////////////////////////////////////////////////////

	object_delete(coind->job);

	coind->job = new YAAMP_JOB;
	memset(coind->job, 0, sizeof(YAAMP_JOB));

	snprintf(coind->job->name, sizeof(coind->job->name), "%s", coind->symbol);

	coind->job->id = job_get_jobid();
	coind->job->templ = templ;

	coind->job->profit = coind_profitability(coind);
	coind->job->maxspeed = coind_nethash(coind) *
		(g_current_algo->profit ? min(1.0, coind_profitability(coind) / g_current_algo->profit) : 1);

	coind->job->coind = coind;

	g_list_job.AddTail(coind->job);
	CommonUnlock(&coind->mutex);

	debuglog("coind_create_job %s %d new job %x\n", coind->name, coind->height, coind->job->id);

	return true;
}
