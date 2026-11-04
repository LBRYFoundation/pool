#include "stratum.h"
#include <mysql/mysqld_error.h>
#include <signal.h>

void db_reconnect(YAAMP_DB *db)
{
	if (g_exiting) {
		db_close(db);
		return;
	}

	mysql_init(&db->mysql);
	for(int i=0; i<6; i++)
	{
		MYSQL *p = mysql_real_connect(&db->mysql, g_sql_host, g_sql_username, g_sql_password, g_sql_database, g_sql_port, 0, 0);
		if(p) break;

		stratumlog("%d, %s\n", i, mysql_error(&db->mysql));
		sleep(10);

		mysql_close(&db->mysql);
		mysql_init(&db->mysql);
	}
}

YAAMP_DB *db_connect()
{
	YAAMP_DB *db = new YAAMP_DB;
	db_reconnect(db);

	return db;
}

void db_close(YAAMP_DB *db)
{
	if (db) {
		mysql_close(&db->mysql);
		delete db;
	}
	db = NULL;
}

char *db_clean_string(YAAMP_DB *db, char *string)
{
	if (!string) return string;
	char *c = string;
	size_t i, len = strlen(string) & 0x1FF;
	for (i = 0; i < len; i++) {
		bool isdigit = (c[i] >= '0' && c[i] <= '9');
		bool isalpha = (c[i] >= 'a' && c[i] <= 'z') || (c[i] >= 'A' && c[i] <= 'Z');
		bool issepch = (c[i] == '=' || c[i] == ',' || c[i] == ';' || c[i] == '.');
		bool isextra = (c[i] == '/' || c[i] == '-' || c[i] == '_');
		if (!isdigit && !isalpha && !issepch && !isextra) { c[i] = '\0'; break; }
	}
	if (db) {
		char raw[512] = { 0 };
		strncpy(raw, string, sizeof(raw) - 1);
		mysql_real_escape_string(&db->mysql, string, raw, strlen(raw));
	}
	return string;
}

// allow more chars without the most hurting ones (bench device names)
static void clean_html(char* string)
{
	char *c = string;
	size_t i, len = strlen(string) & 0x1FF;
	for (i = 0; i < len; i++) {
		if (c[i] == '<' || c[i] == '>' || c[i] == '%' || c[i] == '\\' || c[i] == '"' || c[i] == '\'') {
			c[i] = '\0'; break;
		}
	}
	if (strstr(string, "script")) strcpy(string, "");
}

void db_query(YAAMP_DB *db, const char *format, ...)
{
	if(!db || !format) return;

	va_list arglist, arglist_copy;
	va_start(arglist, format);
	va_copy(arglist_copy, arglist);

	int required_len = vsnprintf(NULL, 0, format, arglist_copy);
	va_end(arglist_copy);

	if (required_len < 0) {
		va_end(arglist);
		return;
	}

	size_t buf_size = (size_t)required_len + 1;
	char *buffer = (char *)malloc(buf_size);
	if(!buffer) {
		va_end(arglist);
		return;
	}

	vsnprintf(buffer, buf_size, format, arglist);
	va_end(arglist);

	while(!g_exiting)
	{
		int res = mysql_query(&db->mysql, buffer);
		if(!res) break;
		res = mysql_errno(&db->mysql);

		stratumlog("SQL ERROR: %d, %s\n", res, mysql_error(&db->mysql));
		if(res == ER_DUP_ENTRY) break;
		if(res != CR_SERVER_GONE_ERROR && res != CR_SERVER_LOST) break;

		usleep(100*YAAMP_MS);
		db_reconnect(db);
	}

	free(buffer);
}

///////////////////////////////////////////////////////////////////////

void db_register_stratum(YAAMP_DB *db)
{
	int pid = getpid();
	int t = time(NULL);
	if(!db) return;

	db_query(db, "INSERT INTO stratums (pid, time, started, algo, url, port) VALUES (%d,%d,%d,'%s','%s',%d) "
		" ON DUPLICATE KEY UPDATE time=%d, algo='%s', url='%s', port=%d",
		pid, t, t, g_stratum_algo, g_tcp_server, g_tcp_port,
		t, g_stratum_algo, g_tcp_server, g_tcp_port
	);
}

void db_update_algos(YAAMP_DB *db)
{
	int pid = getpid();
	int fds = opened_files();
	if(!db) return;

	if(g_current_algo->overflow)
	{
		debuglog("setting overflow\n");
		g_current_algo->overflow = false;

		db_query(db, "UPDATE algos SET overflow=true WHERE name='%s'", g_stratum_algo);
	}

	char symbol[32] = "NULL";
	if(g_list_coind.count == 1) {
		if (g_list_coind.first) {
			CLI li = g_list_coind.first;
			YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
			snprintf(symbol, sizeof(symbol), "'%s'", coind->symbol);
		}
	}

	db_query(db, "UPDATE stratums SET workers=%d, fds=%d, symbol=%s WHERE pid=%d",
		g_list_client.count, fds, symbol, pid);

	///////////////////////////////////////////////////////////////////////////////////////////

	db_query(db, "select name, profit, rent, factor from algos");

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) return;

	MYSQL_ROW row;
	while((row = mysql_fetch_row(result)) != NULL)
	{
		YAAMP_ALGO *algo = stratum_find_algo(row[0]);
		if(!algo) continue;

		if(row[1]) algo->profit = atof(row[1]);
		if(row[2]) algo->rent = atof(row[2]);
		if(row[3]) algo->factor = atof(row[3]);
	}

	mysql_free_result(result);

	////////////////////

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;

		client_reset_multialgo(client, false);
	}

	g_list_client.Leave();
}

////////////////////////////////////////////////////////////////////////////////

void db_update_coinds(YAAMP_DB *db)
{
	if(!db) return;

	for(CLI li = g_list_coind.first; li; li = li->next)
	{
		YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
		if(coind->deleted) continue;
		if(coind->auto_ready) continue;

		debuglog("disabling %s\n", coind->symbol);
		db_query(db, "update coins set auto_ready=%d where id=%d", coind->auto_ready, coind->id);
	}

	////////////////////////////////////////////////////////////////////////////////////////

	db_query(db, "SELECT id, name, rpchost, rpcport, rpcuser, rpcpasswd, rpcencoding, master_wallet, reward, price, "
		"hassubmitblock, txmessage, enable, auto_ready, algo, pool_ttf, charity_address, charity_amount, charity_percent, "
		"reward_mul, symbol, auxpow, actual_ttf, network_ttf, usememorypool, hasmasternodes, algo, symbol2, "
		"rpccurl, rpcssl, rpccert, account, multialgos, max_miners, max_shares, usesegwit "
		"FROM coins WHERE enable AND auto_ready AND algo='%s' ORDER BY index_avg", g_stratum_algo);

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) yaamp_error("Cant query database");

	MYSQL_ROW row;
	g_list_coind.Enter();

	while((row = mysql_fetch_row(result)) != NULL)
	{
		YAAMP_COIND *coind = (YAAMP_COIND *)object_find(&g_list_coind, atoi(row[0]));
		if(!coind)
		{
			coind = new YAAMP_COIND;
			memset(coind, 0, sizeof(YAAMP_COIND));

			coind->newcoind = true;
			coind->newblock = true;
			coind->id = atoi(row[0]);
		}
		else
			coind->newcoind = false;

		snprintf(coind->name, sizeof(coind->name), "%s", row[1] ? row[1] : "");
		snprintf(coind->symbol, sizeof(coind->symbol), "%s", row[20] ? row[20] : "");

		// optional coin filters
		if(coind->newcoind) {
			bool ignore = false;
			if (strlen(g_stratum_coin_include) && !strstr(g_stratum_coin_include, coind->symbol)) ignore = true;
			if (strlen(g_stratum_coin_exclude) && strstr(g_stratum_coin_exclude, coind->symbol)) ignore = true;
			if (ignore) {
				object_delete(coind);
				continue;
			}
		}

		if(row[7]) snprintf(coind->wallet, sizeof(coind->wallet), "%s", row[7]);
		if(row[6]) snprintf(coind->rpcencoding, sizeof(coind->rpcencoding), "%s", row[6]);
		if(row[10]) coind->hassubmitblock = atoi(row[10]);

		coind->rpc.ssl = 0;
		if(row[2]) {
			char buffer[1024];
			char cert[1024];
			snprintf(buffer, sizeof(buffer), "%s", row[2]);
			if (strstr(buffer, "https://") != NULL) {
				snprintf(buffer, sizeof(buffer), "%s", row[2] + 8);
				if (strstr(buffer, "@") != NULL) {
					int p = (int)(strstr(buffer, "@") - buffer);
					strncpy(cert, buffer, sizeof(cert) - 1);
					cert[p] = '\0';
					snprintf(buffer, sizeof(buffer), "%s", row[2] + 8 + p + 1);
				} else {
					strcpy(cert, "yiimp");
				}
				coind->rpc.ssl = 1;
				snprintf(coind->rpc.cert, sizeof(coind->rpc.cert), "/usr/share/ca-certificates/%s.crt", cert);
			}
			strcpy(coind->rpc.cert, "");
			snprintf(coind->rpc.host, sizeof(coind->rpc.host), "%s", buffer);
		}

		if(row[3]) coind->rpc.port = atoi(row[3]);

		if(row[4] && row[5])
		{
			char buffer[1024];
			snprintf(buffer, sizeof(buffer), "%s:%s", row[4], row[5]);

			base64_encode(coind->rpc.credential, buffer);
			coind->rpc.coind = coind;
		}

		if(row[8]) coind->reward = atof(row[8]);
		if(row[9]) coind->price = atof(row[9]);
		if(row[11]) coind->txmessage = atoi(row[11]);
		if(row[12]) coind->enable = atoi(row[12]);
		if(row[13]) coind->auto_ready = atoi(row[13]);
		if(row[15]) coind->pool_ttf = atoi(row[15]);

		if(row[16]) snprintf(coind->charity_address, sizeof(coind->charity_address), "%s", row[16]);
		if(row[17]) coind->charity_amount = atof(row[17]);
		if(row[18]) coind->charity_percent = atof(row[18]);
		if(row[19]) coind->reward_mul = atof(row[19]);
		if(coind->reward_mul <= 0) coind->reward_mul = 1.0;

		if(row[22] && row[23]) coind->actual_ttf = min(atoi(row[22]), atoi(row[23]));
		else if(row[22]) coind->actual_ttf = atoi(row[22]);
		coind->actual_ttf = min(coind->actual_ttf, 120);
		coind->actual_ttf = max(coind->actual_ttf, 20);

		if(row[24]) coind->usememorypool = atoi(row[24]);
		if(row[25]) coind->hasmasternodes = atoi(row[25]);

		if(row[26]) snprintf(coind->algo, sizeof(coind->algo), "%s", row[26]);
		if(row[27]) snprintf(coind->symbol2, sizeof(coind->symbol2), "%s", row[27]);

		if(row[28]) coind->rpc.curl = atoi(row[28]) != 0;
		if(row[29]) coind->rpc.ssl = atoi(row[29]) != 0;
		if(row[30]) snprintf(coind->rpc.cert, sizeof(coind->rpc.cert), "%s", row[30]);

		if(row[31]) snprintf(coind->account, sizeof(coind->account), "%s", row[31]);
		if(row[32]) coind->multialgos = atoi(row[32]);
		if(row[33] && atoi(row[33]) > 0) g_stratum_max_cons = atoi(row[33]);
		if(row[34] && atol(row[34]) > 0) g_max_shares = atol(row[34]);
		if(row[35]) coind->usesegwit = atoi(row[35]) > 0;

		if(coind->usesegwit) g_stratum_segwit = true;

		// Ensure LBC has rpcencoding set to LBC if empty
		if(!strcmp(coind->symbol, "LBC") && !strlen(coind->rpcencoding))
			strcpy(coind->rpcencoding, "LBC");

		////////////////////////////////////////////////////////////////////////////////////////////////////

		if(coind->newcoind)
		{
			debuglog("connecting to coind %s\n", coind->symbol);

			bool b = rpc_connect(&coind->rpc);
			if (!b) {
				debuglog("%s: connect failure\n", coind->symbol);
				object_delete(coind);
				continue;
			}
			coind_init(coind);

			g_list_coind.AddTail(coind);
			usleep(100*YAAMP_MS);
		}
		coind->touch = true;
		coind_create_job(coind);
	}

	mysql_free_result(result);

	for(CLI li = g_list_coind.first; li; li = li->next)
	{
		YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
		if(coind->deleted) continue;

		if(!coind->touch)
		{
			coind_terminate(coind);
			continue;
		}

		coind->touch = false;
	}

	coind_sort();
	g_list_coind.Leave();
}

///////////////////////////////////////////////////////////////////////

static void _json_str_safe(YAAMP_DB *db, json_value *json, const char *key, size_t maxlen, char* out)
{
	json_value *val = json_get_val(json, key);
	out[0] = '\0';
	if (db && val && json_is_string(val)) {
		char str[128] = { 0 };
		char escaped[256] = { 0 };
		snprintf(str, sizeof(str)-1, "%s", json_string_value(val));
		str[maxlen-1] = '\0';
		clean_html(str);
		mysql_real_escape_string(&db->mysql, escaped, str, strlen(str));
		snprintf(out, maxlen, "%s", escaped);
		out[maxlen-1] = '\0';
	}
}
#define json_str_safe(stats, k, out) _json_str_safe(db, stats, k, sizeof(out), out)

static int json_int_safe(json_value *json, const char *key)
{
	json_value *val = json_get_val(json, key);
	return val ? (int) json_integer_value(val) : 0;
}

static double json_double_safe(json_value *json, const char *key)
{
	json_value *val = json_get_val(json, key);
	return val ? json_double_value(val) : 0.;
}

void db_store_stats(YAAMP_DB *db, YAAMP_CLIENT *client, json_value *stats)
{
	int t = time(NULL);
	char sdev[80], stype[8], svid[12], sarch[8];
	char salgo[32], sclient[48], sdriver[32], sos[8];
	double khashes, intensity, throughput;
	int power, freq, memf, realfreq, realmemf, plimit;

	if (!db) return;

	json_str_safe(stats, "algo", salgo);
	if (strcasecmp(g_current_algo->name, salgo) && client->submit_bad) {
		return;
	}

	json_str_safe(stats, "device", sdev);
	json_str_safe(stats, "type", stype);
	json_str_safe(stats, "vendorid", svid);
	json_str_safe(stats, "arch", sarch);
	json_str_safe(stats, "client", sclient);
	json_str_safe(stats, "os", sos);
	json_str_safe(stats, "driver", sdriver);

	power = json_int_safe(stats, "power");
	freq  = json_int_safe(stats, "freq");
	memf  = json_int_safe(stats, "memf");
	realfreq = json_int_safe(stats, "curr_freq");
	realmemf = json_int_safe(stats, "curr_memf");
	plimit = json_int_safe(stats, "plimit");
	intensity  = json_double_safe(stats, "intensity");
	khashes    = json_double_safe(stats, "khashes");
	throughput = json_double_safe(stats, "throughput");
	if (throughput < 0.) throughput = 0.;
	if (khashes < 0. || intensity < 0.) return;

	db_query(db, "INSERT INTO benchmarks("
		"time, algo, type, device, arch, vendorid, os, driver,"
		"client, khps, freq, memf, realfreq, realmemf, power, plimit, "
		"intensity, throughput, userid )"
		"VALUES (%d,'%s','%s','%s','%s','%s','%s','%s',"
		"'%s',%f,%d,%d,%d,%d,%d,%d, %.2f,%.0f,%d)",
		t, g_current_algo->name, stype, sdev, sarch, svid, sos, sdriver,
		sclient, khashes, freq, memf, realfreq, realmemf, power, plimit,
		intensity, throughput, client->userid);
}
