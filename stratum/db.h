class YAAMP_CLIENT;

struct YAAMP_DB
{
	MYSQL mysql;
	bool initialized;	// mysql handle has been mysql_init()'ed and must be closed before reuse
};

YAAMP_DB *db_connect();

char *db_clean_string(YAAMP_DB *db, char *string);

void db_close(YAAMP_DB *p);
// Returns true on success. Transient errors (lost connection, deadlock, lock wait timeout)
// are retried internally; other errors are logged with the failing query and return false.
bool db_query(YAAMP_DB *db, const char *format, ...);

// Verify at startup that every table/column used by stratum exists and that
// address columns are wide enough for Bech32 (lbc1...) addresses. Exits on failure.
void db_check_schema(YAAMP_DB *db);

void db_register_stratum(YAAMP_DB *db);
void db_update_algos(YAAMP_DB *db);
void db_update_coinds(YAAMP_DB *db);

void db_add_user(YAAMP_DB *db, YAAMP_CLIENT *client);

void db_add_worker(YAAMP_DB *db, YAAMP_CLIENT *client);
void db_clear_worker(YAAMP_DB *db, YAAMP_CLIENT *client);
void db_update_worker(YAAMP_DB *db, YAAMP_CLIENT *client);
void db_update_workers(YAAMP_DB *db);

void db_init_user_coinid(YAAMP_DB *db, YAAMP_CLIENT *client);

void db_store_stats(YAAMP_DB *db, YAAMP_CLIENT *client, json_value *stats);
