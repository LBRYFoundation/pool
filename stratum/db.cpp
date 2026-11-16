#include "stratum.h"
#include <mysql/mysqld_error.h>
#include <signal.h>

// Error codes not present in every MySQL/MariaDB client header version
#ifndef CR_SERVER_LOST_EXTENDED
#define CR_SERVER_LOST_EXTENDED 2055
#endif
#ifndef ER_CONNECTION_KILLED
#define ER_CONNECTION_KILLED 1927	/* MariaDB */
#endif

#define DB_DEADLOCK_RETRIES 5

void db_reconnect(YAAMP_DB *db)
{
	// The owner of the handle closes it on shutdown (db_close)
	if (g_exiting) return;

	unsigned int timeout = 10;
	for(int i=0; !g_exiting; i++)
	{
		// Release the previous handle before re-initializing it (avoid leaking it)
		if (db->initialized) mysql_close(&db->mysql);
		mysql_init(&db->mysql);
		db->initialized = true;
		mysql_options(&db->mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

		MYSQL *p = mysql_real_connect(&db->mysql, g_sql_host, g_sql_username, g_sql_password, g_sql_database, g_sql_port, 0, 0);
		if(p) {
			if (i) stratumlog("database connection restored after %d attempts\n", i);
			return;
		}

		stratumlog("database connect attempt %d failed: %s\n", i + 1, mysql_error(&db->mysql));
		sleep(i < 6 ? 2 : 10);
	}
}

YAAMP_DB *db_connect()
{
	YAAMP_DB *db = new YAAMP_DB();	// value-initialized: initialized=false
	db_reconnect(db);

	return db;
}

void db_close(YAAMP_DB *db)
{
	if (db) {
		if (db->initialized) mysql_close(&db->mysql);
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

// Connection-level failures: reconnect and retry the query
static bool db_error_is_connection(unsigned int err)
{
	switch (err) {
	case CR_SERVER_GONE_ERROR:	// 2006
	case CR_SERVER_LOST:		// 2013
	case CR_SERVER_LOST_EXTENDED:	// 2055
	case CR_CONNECTION_ERROR:	// 2002
	case CR_CONN_HOST_ERROR:	// 2003
	case CR_COMMANDS_OUT_OF_SYNC:	// 2014, a fresh connection resets the protocol state
	case ER_CONNECTION_KILLED:	// 1927
	case ER_SERVER_SHUTDOWN:	// 1053
	case ER_CON_COUNT_ERROR:	// 1040 too many connections
		return true;
	}
	return false;
}

// Lock conflicts with concurrent writers (web cron/payments): retry the query on the same connection
static bool db_error_is_lock_conflict(unsigned int err)
{
	return err == ER_LOCK_DEADLOCK || err == ER_LOCK_WAIT_TIMEOUT;	// 1213, 1205
}

bool db_query(YAAMP_DB *db, const char *format, ...)
{
	if(!db || !format) return false;

	va_list arglist, arglist_copy;
	va_start(arglist, format);
	va_copy(arglist_copy, arglist);

	int required_len = vsnprintf(NULL, 0, format, arglist_copy);
	va_end(arglist_copy);

	if (required_len < 0) {
		va_end(arglist);
		return false;
	}

	size_t buf_size = (size_t)required_len + 1;
	char *buffer = (char *)malloc(buf_size);
	if(!buffer) {
		va_end(arglist);
		return false;
	}

	vsnprintf(buffer, buf_size, format, arglist);
	va_end(arglist);

	bool ok = false;
	int lock_retries = 0;
	while(!g_exiting)
	{
		if(!mysql_query(&db->mysql, buffer)) {
			ok = true;
			break;
		}
		unsigned int err = mysql_errno(&db->mysql);

		if(err == ER_DUP_ENTRY) {
			// rarely seen on new user creation, harmless
			debuglog("SQL duplicate entry: %s\n", mysql_error(&db->mysql));
			break;
		}

		if(db_error_is_lock_conflict(err) && lock_retries < DB_DEADLOCK_RETRIES) {
			lock_retries++;
			stratumlog("SQL lock conflict %u (%s), retry %d/%d\n", err, mysql_error(&db->mysql),
				lock_retries, DB_DEADLOCK_RETRIES);
			usleep(lock_retries * 100 * YAAMP_MS);
			continue;
		}

		if(db_error_is_connection(err)) {
			stratumlog("SQL connection error %u (%s), reconnecting\n", err, mysql_error(&db->mysql));
			usleep(100*YAAMP_MS);
			db_reconnect(db);
			continue;
		}

		// Anything else is a code or schema bug: log it with the failing query and keep running
		// (exiting would disconnect every miner; the startup schema check catches config issues).
		stratumlog("SQL ERROR %u: %s\n", err, mysql_error(&db->mysql));
		stratumlog("SQL QUERY: %.400s%s\n", buffer, strlen(buffer) > 400 ? "..." : "");
		break;
	}

	free(buffer);
	return ok;
}

///////////////////////////////////////////////////////////////////////
// Schema contract

// Column order matters: db_update_coinds() reads these by index
#define DB_COINS_COLUMNS \
	"id, name, rpchost, rpcport, rpcuser, rpcpasswd, rpcencoding, master_wallet, reward, price, " /* 0-9 */ \
	"hassubmitblock, txmessage, enable, auto_ready, algo, pool_ttf, charity_address, charity_amount, charity_percent, " /* 10-18 */ \
	"reward_mul, symbol, actual_ttf, network_ttf, usememorypool, " /* 19-23 */ \
	"rpccurl, rpcssl, rpccert, account, max_miners, max_shares, usesegwit" /* 24-30 */

struct DB_SCHEMA_TABLE {
	const char *table;
	const char *columns;
	bool required;	// false: only used by optional features, warn instead of exiting
};

static const DB_SCHEMA_TABLE db_schema_tables[] = {
	{ "stratums", "pid, time, started, algo, url, port, workers, fds, symbol", true },
	{ "algos", "name, profit, factor, overflow", true },
	{ "coins", DB_COINS_COLUMNS ", installed", true },
	{ "accounts", "id, is_locked, logtraffic, coinid, donation, username, coinsymbol, balance, hostaddr, swap_time", true },
	{ "payouts", "account_id, tx", true },
	{ "balanceuser", "userid, pending, time", true },
	{ "workers", "id, userid, ip, name, difficulty, version, password, worker, algo, time, pid, subscribe", true },
	{ "shares", "userid, workerid, coinid, jobid, pid, valid, extranonce1, difficulty, share_diff, time, algo, error", true },
	{ "blocks", "height, blockhash, coin_id, userid, workerid, category, difficulty, difficulty_user, time, algo, segwit", true },
	{ "benchmarks", "time, algo, type, device, arch, vendorid, os, driver, client, khps, freq, memf, "
		"realfreq, realmemf, power, plimit, intensity, throughput, userid", false },
};

struct DB_SCHEMA_WIDTH {
	const char *table;
	const char *column;
	int min_len;
	bool required;
	const char *reason;
};

// Bech32 lbc1... addresses are 43 (P2WPKH) to 63 (P2WSH/P2TR) chars
static const DB_SCHEMA_WIDTH db_schema_widths[] = {
	{ "accounts", "username", 64, true, "Bech32 (lbc1...) miner addresses" },
	{ "workers", "name", 64, true, "Bech32 (lbc1...) miner addresses" },
	{ "workers", "version", 64, true, "miner version strings (truncated to 64)" },
	{ "workers", "password", 64, true, "miner password strings (truncated to 64)" },
	{ "workers", "worker", 64, true, "worker names (truncated to 64)" },
	{ "workers", "ip", 45, false, "IPv6 client addresses" },
	{ "accounts", "hostaddr", 45, false, "IPv6 client addresses" },
};

static int db_column_length(YAAMP_DB *db, const char *table, const char *column)
{
	int len = -1;
	if(!db_query(db, "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS "
		"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='%s' AND COLUMN_NAME='%s'", table, column))
		return len;

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) return len;
	MYSQL_ROW row = mysql_fetch_row(result);
	if(row && row[0]) len = atoi(row[0]);
	mysql_free_result(result);
	return len;
}

void db_check_schema(YAAMP_DB *db)
{
	int errors = 0;
	if(!db) yaamp_error("schema check: no database connection");

	for(size_t i = 0; i < sizeof(db_schema_tables)/sizeof(db_schema_tables[0]); i++)
	{
		const DB_SCHEMA_TABLE *t = &db_schema_tables[i];
		bool ok = db_query(db, "SELECT %s FROM %s LIMIT 0", t->columns, t->table);
		MYSQL_RES *result = ok ? mysql_store_result(&db->mysql) : NULL;
		if(result) mysql_free_result(result);
		if(ok) continue;

		stratumlog("%s: table '%s' is missing or lacks one of the columns: %s\n",
			t->required ? "SCHEMA ERROR" : "SCHEMA WARNING", t->table, t->columns);
		if(t->required) errors++;
	}

	for(size_t i = 0; i < sizeof(db_schema_widths)/sizeof(db_schema_widths[0]); i++)
	{
		const DB_SCHEMA_WIDTH *w = &db_schema_widths[i];
		int len = db_column_length(db, w->table, w->column);
		if(len < 0 || len >= w->min_len) continue;	// missing columns are reported above

		stratumlog("%s: %s.%s is varchar(%d), needs at least %d for %s\n",
			w->required ? "SCHEMA ERROR" : "SCHEMA WARNING", w->table, w->column, len, w->min_len, w->reason);
		if(w->required) errors++;
	}

	if(errors) {
		stratumlog("database schema check failed with %d error(s); apply the migrations in sql/ "
			"(e.g. sql/2026-11-04-lbc_stratum_widths.sql)\n", errors);
		exit(1);
	}
	debuglog("database schema check passed\n");
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

	db_query(db, "select name, profit, factor from algos");

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) return;

	MYSQL_ROW row;
	while((row = mysql_fetch_row(result)) != NULL)
	{
		YAAMP_ALGO *algo = stratum_find_algo(row[0]);
		if(!algo) continue;

		if(row[1]) algo->profit = atof(row[1]);
		if(row[2]) algo->factor = atof(row[2]);
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

	db_query(db, "SELECT " DB_COINS_COLUMNS " FROM coins WHERE enable AND auto_ready AND algo='%s' ORDER BY id", g_stratum_algo);

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) {
		// Error already logged by db_query(); keep the current coin list and retry next cycle
		stratumlog("unable to load coins from database, keeping current list\n");
		return;
	}

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

		if(row[21] && row[22]) coind->actual_ttf = min(atoi(row[21]), atoi(row[22]));
		else if(row[21]) coind->actual_ttf = atoi(row[21]);
		coind->actual_ttf = min(coind->actual_ttf, 120);
		coind->actual_ttf = max(coind->actual_ttf, 20);

		if(row[23]) coind->usememorypool = atoi(row[23]);

		if(row[14]) snprintf(coind->algo, sizeof(coind->algo), "%s", row[14]);

		if(row[24]) coind->rpc.curl = atoi(row[24]) != 0;
		if(row[25]) coind->rpc.ssl = atoi(row[25]) != 0;
		if(row[26]) snprintf(coind->rpc.cert, sizeof(coind->rpc.cert), "%s", row[26]);

		if(row[27]) snprintf(coind->account, sizeof(coind->account), "%s", row[27]);
		if(row[28] && atoi(row[28]) > 0) g_stratum_max_cons = atoi(row[28]);
		if(row[29] && atol(row[29]) > 0) g_max_shares = atol(row[29]);
		if(row[30]) coind->usesegwit = atoi(row[30]) > 0;

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
