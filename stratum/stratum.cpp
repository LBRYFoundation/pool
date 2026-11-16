#include "stratum.h"
#include <signal.h>
#include <sys/resource.h>

CommonList g_list_coind;
CommonList g_list_client;
CommonList g_list_job;
CommonList g_list_share;
CommonList g_list_worker;
CommonList g_list_block;
CommonList g_list_source;

int g_tcp_port;

char g_tcp_server[1024];
char g_tcp_password[1024];

char g_sql_host[1024];
char g_sql_database[1024];
char g_sql_username[1024];
char g_sql_password[1024];
int g_sql_port = 3306;

char g_stratum_coin_include[256];
char g_stratum_coin_exclude[256];

char g_stratum_algo[256];
char g_stratum_coinbase_sig[128] = "/lbrypool.net/";
double g_stratum_difficulty;
double g_stratum_min_diff;
double g_stratum_max_diff;

int g_stratum_max_ttf;
int g_stratum_max_cons = 5000;
bool g_stratum_reconnect;
bool g_stratum_segwit = false;

int g_limit_txs_per_block = 0;

bool g_handle_haproxy_ips = false;
int g_socket_recv_timeout = 600;

bool g_debuglog_client;
bool g_debuglog_hash;
bool g_debuglog_socket;
bool g_debuglog_rpc;
bool g_debuglog_list;

bool g_autoexchange = false;

uint64_t g_max_shares = 0;
uint64_t g_shares_counter = 0;
uint64_t g_shares_log = 0;

bool g_allow_rolltime = true;
time_t g_last_broadcasted = 0;
YAAMP_DB *g_db = NULL;

pthread_mutex_t g_db_mutex;
pthread_mutex_t g_nonce1_mutex;
pthread_mutex_t g_job_create_mutex;

struct ifaddrs *g_ifaddr;

volatile bool g_exiting = false;

void *stratum_thread(void *p);
void *monitor_thread(void *p);

////////////////////////////////////////////////////////////////////////////////////////

YAAMP_ALGO g_algos[] =
{
	{"lbry", lbry_hash, 0x100, 0, 0},
	{"sha256", sha256_double_hash, 1, 0, 0},
	{"", NULL, 0, 0, 0},
};

YAAMP_ALGO *g_current_algo = NULL;

YAAMP_ALGO *stratum_find_algo(const char *name)
{
	for(int i=0; g_algos[i].name[0]; i++)
		if(!strcmp(name, g_algos[i].name))
			return &g_algos[i];

	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		printf("usage: %s <algo>\n", argv[0]);
		return 1;
	}

	srand(time(NULL));
	getifaddrs(&g_ifaddr);

	initlog(argv[1]);

	char configfile[1024];
	snprintf(configfile, sizeof(configfile), "%s.conf", argv[1]);

	dictionary *ini = iniparser_load(configfile);
	if(!ini)
	{
		debuglog("cant load config file %s\n", configfile);
		return 1;
	}

	g_tcp_port = iniparser_getint(ini, "TCP:port", 3334);
	snprintf(g_tcp_server, sizeof(g_tcp_server), "%s", iniparser_getstring(ini, "TCP:server", "127.0.0.1"));
	snprintf(g_tcp_password, sizeof(g_tcp_password), "%s", iniparser_getstring(ini, "TCP:password", ""));

	snprintf(g_sql_host, sizeof(g_sql_host), "%s", iniparser_getstring(ini, "SQL:host", "localhost"));
	snprintf(g_sql_database, sizeof(g_sql_database), "%s", iniparser_getstring(ini, "SQL:database", "yaamp"));
	snprintf(g_sql_username, sizeof(g_sql_username), "%s", iniparser_getstring(ini, "SQL:username", "root"));
	snprintf(g_sql_password, sizeof(g_sql_password), "%s", iniparser_getstring(ini, "SQL:password", ""));
	g_sql_port = iniparser_getint(ini, "SQL:port", 3306);

	// optional coin filters (to mine only one on a special port or a test instance)
	char *coin_filter = iniparser_getstring(ini, "WALLETS:include", NULL);
	snprintf(g_stratum_coin_include, sizeof(g_stratum_coin_include), "%s", coin_filter ? coin_filter : "");
	coin_filter = iniparser_getstring(ini, "WALLETS:exclude", NULL);
	snprintf(g_stratum_coin_exclude, sizeof(g_stratum_coin_exclude), "%s", coin_filter ? coin_filter : "");

	snprintf(g_stratum_algo, sizeof(g_stratum_algo), "%s", iniparser_getstring(ini, "STRATUM:algo", "lbry"));
	char *cb_sig = iniparser_getstring(ini, "STRATUM:coinbase_sig", NULL);
	if (cb_sig && strlen(cb_sig) > 0) {
		// The full coinbase scriptSig (height + flags + time + extranonce + sig) must be <= 100 bytes
		if (strlen(cb_sig) > YAAMP_COINBASE_SIG_MAX)
			stratumlog("WARNING: coinbase_sig '%s' is longer than %d bytes, truncating\n", cb_sig, YAAMP_COINBASE_SIG_MAX);
		snprintf(g_stratum_coinbase_sig, sizeof(g_stratum_coinbase_sig), "%.*s", YAAMP_COINBASE_SIG_MAX, cb_sig);
	}
	g_stratum_difficulty = iniparser_getdouble(ini, "STRATUM:difficulty", 16);
	g_stratum_min_diff = iniparser_getdouble(ini, "STRATUM:diff_min", g_stratum_difficulty/2);
	g_stratum_max_diff = iniparser_getdouble(ini, "STRATUM:diff_max", g_stratum_difficulty*8192);

	g_stratum_max_cons = iniparser_getint(ini, "STRATUM:max_cons", 5000);
	g_stratum_max_ttf = iniparser_getint(ini, "STRATUM:max_ttf", 0x70000000);
	g_stratum_reconnect = iniparser_getint(ini, "STRATUM:reconnect", true);
	g_handle_haproxy_ips = iniparser_getint(ini, "STRATUM:haproxy_ips", g_handle_haproxy_ips);
	g_socket_recv_timeout = iniparser_getint(ini, "STRATUM:recv_timeout", 600);

	g_max_shares = iniparser_getint(ini, "STRATUM:max_shares", g_max_shares);
	g_limit_txs_per_block = iniparser_getint(ini, "STRATUM:max_txs_per_block", 0);

	g_debuglog_client = iniparser_getint(ini, "DEBUGLOG:client", false);
	g_debuglog_hash = iniparser_getint(ini, "DEBUGLOG:hash", false);
	g_debuglog_socket = iniparser_getint(ini, "DEBUGLOG:socket", false);
	g_debuglog_rpc = iniparser_getint(ini, "DEBUGLOG:rpc", false);
	g_debuglog_list = iniparser_getint(ini, "DEBUGLOG:list", false);

	iniparser_freedict(ini);

	g_current_algo = stratum_find_algo(g_stratum_algo);

	if(!g_current_algo) yaamp_error("invalid algo");
	if(!g_current_algo->hash_function) yaamp_error("no hash function");

	struct rlimit rlim_threads = {0x8000, 0x8000};
	setrlimit(RLIMIT_NPROC, &rlim_threads);

	stratumlogdate("starting stratum for %s on %s:%d\n",
		g_current_algo->name, g_tcp_server, g_tcp_port);

	g_allow_rolltime = true;

	g_db = db_connect();
	if(!g_db) yaamp_error("Cant connect database");

	yaamp_create_mutex(&g_db_mutex);
	yaamp_create_mutex(&g_nonce1_mutex);
	yaamp_create_mutex(&g_job_create_mutex);

	YAAMP_DB *db = db_connect();
	if(!db) yaamp_error("Cant connect database");

	// Fail fast on schema problems before accepting any miner
	db_check_schema(db);

	db_register_stratum(db);
	db_update_algos(db);
	db_update_coinds(db);

	sleep(2);
	job_init();

	////////////////////////////////////////////////

	pthread_t thread1;
	pthread_create(&thread1, NULL, monitor_thread, NULL);

	pthread_t thread2;
	pthread_create(&thread2, NULL, stratum_thread, NULL);

	sleep(20);

	while(!g_exiting)
	{
		db_register_stratum(db);
		db_update_workers(db);
		db_update_algos(db);
		db_update_coinds(db);

		share_write(db);
		share_prune(db);

		block_prune(db);

		sleep(1);
		job_signal();

		////////////////////////////////////

		object_prune(&g_list_coind, coind_delete);
		object_prune(&g_list_job, job_delete);
		object_prune(&g_list_client, client_delete);
		object_prune(&g_list_block, block_delete);
		object_prune(&g_list_worker, worker_delete);
		object_prune(&g_list_share, share_delete);

		if (!g_exiting) sleep(20);
	}

	stratumlog("closing database...\n");
	db_close(db);

	pthread_join(thread2, NULL);
	db_close(g_db); // client threads (called by stratum one)

	closelogs();

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

void *monitor_thread(void *p)
{
	(void)p;
	while(!g_exiting)
	{
		sleep(120);

		if(g_last_broadcasted + YAAMP_MAXJOBDELAY < time(NULL))
		{
			g_exiting = true;
			stratumlogdate("%s dead lock, exiting...\n", g_stratum_algo);
			exit(1);
		}

		if(g_max_shares && g_shares_counter) {

			if((g_shares_counter - g_shares_log) > 10000) {
				stratumlogdate("%s %luK shares...\n", g_stratum_algo, (g_shares_counter/1000u));
				g_shares_log = g_shares_counter;
			}

			if(g_shares_counter > g_max_shares) {
				g_exiting = true;
				stratumlogdate("%s need a restart (%lu shares), exiting...\n", g_stratum_algo, (unsigned long) g_max_shares);
				exit(1);
			}
		}
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////

void *stratum_thread(void *p)
{
	(void)p;
	int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(listen_sock <= 0) yaamp_error("socket");

	int optval = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

	struct sockaddr_in serv;

	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(g_tcp_port);

	int res = bind(listen_sock, (struct sockaddr*)&serv, sizeof(serv));
	if(res < 0) yaamp_error("bind");

	res = listen(listen_sock, 4096);
	if(res < 0) yaamp_error("listen");

	/////////////////////////////////////////////////////////////////////////

	int failcount = 0;
	while(!g_exiting)
	{
		int sock = accept(listen_sock, NULL, NULL);
		if(sock <= 0)
		{
			int error = errno;
			stratumlog("%s socket accept() error %d\n", g_stratum_algo, error);
			failcount++;
			usleep(50000);
			if (error == 24 && failcount > 5) {
				g_exiting = true; // happen when max open files is reached (see ulimit)
				stratumlogdate("%s too much socket failure, exiting...\n", g_stratum_algo);
				exit(error);
			}
			continue;
		}

		failcount = 0;
		pthread_t thread;
		int res = pthread_create(&thread, NULL, client_thread, (void *)(long)sock);
		if(res != 0)
		{
			int error = errno;
			close(sock);
			g_exiting = true;
			stratumlog("%s pthread_create error %d %d\n", g_stratum_algo, res, error);
		}

		pthread_detach(thread);
	}
	return NULL;
}
