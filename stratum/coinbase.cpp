// http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html

#include "stratum.h"

#define TX_VALUE(v, s)	((unsigned int)(v>>s)&0xff)

static void encode_tx_value(char *encoded, json_int_t value)
{
	sprintf(encoded, "%02x%02x%02x%02x%02x%02x%02x%02x",
		TX_VALUE(value, 0), TX_VALUE(value, 8), TX_VALUE(value, 16), TX_VALUE(value, 24),
		TX_VALUE(value, 32), TX_VALUE(value, 40), TX_VALUE(value, 48), TX_VALUE(value, 56));
}

static void p2sh_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *payee)
{
	char evalue[32];
	char coinb2_part[1032];
	char coinb2_len[4];
	snprintf(coinb2_part, sizeof(coinb2_part), "a9%02x%s87", (unsigned int)(strlen(payee) >> 1) & 0xFF, payee);
	snprintf(coinb2_len, sizeof(coinb2_len), "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
	encode_tx_value(evalue, amount);
	strcat(data, evalue);
	strcat(data, coinb2_len);
	strcat(data, coinb2_part);
}

static void job_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *key)
{
	char evalue[32];

	if(coind->raw_script_pubkey && !key) {
		encode_tx_value(evalue, amount);
		sprintf(data + strlen(data), "%s%02x%s", evalue, (unsigned int)(strlen(coind->script_pubkey) >> 1) & 0xFF, coind->script_pubkey);
		return;
	}

	if(coind->p2sh_address && !key) {
		p2sh_pack_tx(coind, data, amount, coind->script_pubkey);
		return;
	}

	encode_tx_value(evalue, amount);
	sprintf(data + strlen(data), "%s", evalue);
	sprintf(data + strlen(data), "1976a914%s88ac", key ? key : coind->script_pubkey);
}

void coinbase_create(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *json_result)
{
	char eheight[32], etime[32];
	char entime[32] = { 0 };
	char commitment[160] = { 0 };

	ser_number(templ->height, eheight);
	ser_number(time(NULL), etime);

	char eversion1[32] = "01000000";
	if(coind->txmessage)
		strcpy(eversion1, "02000000");

	char script1[1024];
	snprintf(script1, sizeof(script1), "%s%s%s08", eheight, templ->flags, etime);

	// Encode configurable coinbase signature (default "/lbrypool.net/") into hex.
	// Consensus: total coinbase scriptSig must be <= 100 bytes.
	char script2[256] = { 0 };
	const char *sig = strlen(g_stratum_coinbase_sig) ? g_stratum_coinbase_sig : "/lbrypool.net/";
	size_t sig_len = strlen(sig);
	int sig_room = 100 - (int)(strlen(script1)/2) - 8;
	size_t sig_max = sig_room > 0 ? (size_t)sig_room : 0;
	if (sig_max > YAAMP_COINBASE_SIG_MAX) sig_max = YAAMP_COINBASE_SIG_MAX;
	if (sig_len > sig_max) {
		static bool warned = false;
		if (!warned) {
			stratumlog("WARNING: coinbase signature truncated from %d to %d bytes to keep scriptSig <= 100 bytes\n",
				(int)sig_len, (int)sig_max);
			warned = true;
		}
		sig_len = sig_max;
	}
	hexlify(script2, (const unsigned char *)sig, (int)sig_len);

	int script_len = (int)(strlen(script1)/2 + strlen(script2)/2 + 8);
	snprintf(templ->coinb1, sizeof(templ->coinb1), "%s%s01"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"ffffffff%02x%s", eversion1, entime, script_len & 0xFF, script1);

	snprintf(templ->coinb2, sizeof(templ->coinb2), "%s00000000", script2);

	// segwit commitment, if needed
	if (templ->has_segwit_txs)
		snprintf(commitment, sizeof(commitment), "0000000000000000%02x%s", (unsigned int)(strlen(coind->commitment)/2) & 0xFF, coind->commitment);

	json_int_t available = templ->value;

	// Optional pool charity/dev fee split if configured on the coin record
	if(coind->charity_percent > 0 && strlen(coind->charity_address) > 0)
	{
		char script_payee[1024] = { 0 };
		char charity_payee[1024] = { 0 };
		const char *payee = json_get_string(json_result, "payee");
		if (payee) snprintf(charity_payee, sizeof(charity_payee), "%s", payee);
		else snprintf(charity_payee, sizeof(charity_payee), "%s", coind->charity_address);

		base58_decode(charity_payee, script_payee);

		json_int_t charity_amount = json_get_int(json_result, "payee_amount");
		if (charity_amount <= 0)
			charity_amount = (available * coind->charity_percent) / 100;

		available -= charity_amount;
		coind->charity_amount = charity_amount;

		if (templ->has_segwit_txs) {
			strcat(templ->coinb2, "03");
			strcat(templ->coinb2, commitment);
		} else {
			strcat(templ->coinb2, "02");
		}
		job_pack_tx(coind, templ->coinb2, available, NULL);
		job_pack_tx(coind, templ->coinb2, charity_amount, script_payee);
		strcat(templ->coinb2, "00000000"); // locktime

		coind->reward = (double)available / 100000000 * coind->reward_mul;
		return;
	}

	if (templ->has_segwit_txs) {
		strcat(templ->coinb2, "02");
		strcat(templ->coinb2, commitment);
	} else {
		strcat(templ->coinb2, "01");
	}

	job_pack_tx(coind, templ->coinb2, available, NULL);
	strcat(templ->coinb2, "00000000"); // locktime

	coind->reward = (double)available / 100000000 * coind->reward_mul;
}
