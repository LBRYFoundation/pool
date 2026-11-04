#include "stratum.h"

static YAAMP_WORKER *share_find_worker(YAAMP_CLIENT *client, YAAMP_JOB *job, bool valid)
{
	for(CLI li = g_list_worker.first; li; li = li->next)
	{
		YAAMP_WORKER *worker = (YAAMP_WORKER *)li->data;
		if(worker->deleted) continue;

		if(	worker->userid == client->userid &&
			worker->workerid == client->workerid &&
			worker->valid == valid)
		{
			if(!job && !worker->coinid)
				return worker;
			else if(!job)
				continue;
			else if(job->coind && worker->coinid == job->coind->id)
				return worker;
		}
	}

	return NULL;
}

static void share_add_worker(YAAMP_CLIENT *client, YAAMP_JOB *job, bool valid, char *ntime, double share_diff, int error_number)
{
	g_list_worker.Enter();

	YAAMP_WORKER *worker = share_find_worker(client, job, valid);
	if(!worker)
	{
		worker = new YAAMP_WORKER;
		memset(worker, 0, sizeof(YAAMP_WORKER));

		worker->userid = client->userid;
		worker->workerid = client->workerid;
		worker->coinid = job ? (job->coind ? job->coind->id : 0) : 0;
		worker->valid = valid;
		worker->error_number = error_number;
		sscanf(ntime, "%x", &worker->ntime);
		worker->share_diff = share_diff;

		if(g_stratum_reconnect)
			worker->extranonce1 = !client->reconnecting && (client->reconnectable || client->extranonce_subscribe);
		else
			worker->extranonce1 = client->extranonce_subscribe;

		g_list_worker.AddTail(worker);
	}

	if(valid)
	{
		worker->difficulty += client->difficulty_actual / g_current_algo->diff_multiplier;
		client->speed += client->difficulty_actual / g_current_algo->diff_multiplier * 42;
	}

	g_list_worker.Leave();
}

/////////////////////////////////////////////////////////////////////////

void share_add(YAAMP_CLIENT *client, YAAMP_JOB *job, bool valid, char *extranonce2, char *ntime, char *nonce, double share_diff, int error_number)
{
	g_shares_counter++;
	share_add_worker(client, job, valid, ntime, share_diff, error_number);

	YAAMP_SHARE *share = new YAAMP_SHARE;
	memset(share, 0, sizeof(YAAMP_SHARE));

	share->jobid = job ? job->id : 0;
	snprintf(share->extranonce2, sizeof(share->extranonce2), "%s", extranonce2);
	snprintf(share->ntime, sizeof(share->ntime), "%s", ntime);
	snprintf(share->nonce, sizeof(share->nonce), "%s", nonce);
	snprintf(share->nonce1, sizeof(share->nonce1), "%s", client->extranonce1);

	g_list_share.AddTail(share);
}

YAAMP_SHARE *share_find(int jobid, char *extranonce2, char *ntime, char *nonce, char *nonce1)
{
	g_list_share.Enter();
	for(CLI li = g_list_share.first; li; li = li->next)
	{
		YAAMP_SHARE *share = (YAAMP_SHARE *)li->data;
		if(share->deleted) continue;

		if(	share->jobid == jobid &&
			!strcmp(share->extranonce2, extranonce2) && !strcmp(share->ntime, ntime) &&
			!strcmp(share->nonce, nonce) && !strcmp(share->nonce1, nonce1))
		{
			g_list_share.Leave();
			return share;
		}
	}

	g_list_share.Leave();
	return NULL;
}

void share_write(YAAMP_DB *db)
{
	int pid = getpid();
	int count = 0;
	int now = time(NULL);

	char buffer[1024*1024] = "insert into shares (userid, workerid, coinid, jobid, pid, valid, extranonce1, difficulty, share_diff, time, algo, error) values ";
	g_list_worker.Enter();

	for(CLI li = g_list_worker.first; li; li = li->next)
	{
		YAAMP_WORKER *worker = (YAAMP_WORKER *)li->data;
		if(worker->deleted) continue;

		if(!worker->workerid) {
			object_delete(worker);
			continue;
		}

		if(count) strcat(buffer, ",");
		sprintf(buffer+strlen(buffer), "(%d, %d, %d, 0, %d, %d, %d, %f, %f, %d, '%s', %d)",
			worker->userid, worker->workerid, worker->coinid, pid,
			worker->valid, worker->extranonce1, worker->difficulty, worker->share_diff, now, g_stratum_algo, worker->error_number);

		if((now - (int)worker->ntime) > 15*60 || (int)worker->ntime > now) {
			debuglog("ntime warning: value %u (%08x) offset %d secs from uid %d\n", worker->ntime, worker->ntime, (now - (int)worker->ntime), worker->userid);
		}

		if(++count >= 1000)
		{
			db_query(db, "%s", buffer);

			strcpy(buffer, "insert into shares (userid, workerid, coinid, jobid, pid, valid, extranonce1, difficulty, share_diff, time, algo, error) values ");
			count = 0;
		}

		object_delete(worker);
	}

	g_list_worker.Leave();
	if(count) db_query(db, "%s", buffer);
}

void share_prune(YAAMP_DB *db)
{
	g_list_share.Enter();
	for(CLI li = g_list_share.first; li; li = li->next)
	{
		YAAMP_SHARE *share = (YAAMP_SHARE *)li->data;
		if(share->deleted) continue;

		YAAMP_JOB *job = (YAAMP_JOB *)object_find(&g_list_job, share->jobid);
		if(job) continue;

		object_delete(share);
	}

	g_list_share.Leave();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

void block_prune(YAAMP_DB *db)
{
	int count = 0;
	char buffer[128*1024] = "insert into blocks (height, blockhash, coin_id, userid, workerid, category, difficulty, difficulty_user, time, algo, segwit) values ";

	g_list_block.Enter();
	for(CLI li = g_list_block.first; li; li = li->next)
	{
		YAAMP_BLOCK *block = (YAAMP_BLOCK *)li->data;
		if(!block->confirmed)
		{
			int elapsed = 30;
			if((block->created + elapsed) < time(NULL))
				object_delete(block);

			continue;
		}

		if(count) strcat(buffer, ",");
		sprintf(buffer+strlen(buffer), "(%d, '%s', %d, %d, %d, 'new', %f, %f, %d, '%s', %d)",
			block->height, block->hash, block->coinid, block->userid, block->workerid,
			block->difficulty, block->difficulty_user, (int)block->created, g_stratum_algo, block->segwit?1:0);

		object_delete(block);
		count++;
	}

	g_list_block.Leave();
	if(count) db_query(db, "%s", buffer);
}

void block_add(int userid, int workerid, int coinid, int height, double diff, double diff_user, const char *h1, const char *h2, int segwit)
{
	YAAMP_BLOCK *block = new YAAMP_BLOCK;
	memset(block, 0, sizeof(YAAMP_BLOCK));

	block->created = time(NULL);
	block->userid = userid;
	block->workerid = workerid;
	block->coinid = coinid;
	block->height = height;
	block->difficulty = diff;
	block->difficulty_user = diff_user;
	block->segwit = segwit;

	snprintf(block->hash1, sizeof(block->hash1), "%s", h1);
	snprintf(block->hash2, sizeof(block->hash2), "%s", h2);

	g_list_block.AddTail(block);
}

// called from blocknotify tool
bool block_confirm(int coinid, const char *blockhash)
{
	char hash[192];
	if(strlen(blockhash) < 64) return false;

	snprintf(hash, sizeof(hash), "%s", blockhash);

	for(CLI li = g_list_block.first; li; li = li->next)
	{
		YAAMP_BLOCK *block = (YAAMP_BLOCK *)li->data;
		if(block->coinid == coinid && !block->deleted)
		{
			if(strcmp(block->hash1, hash) && strcmp(block->hash2, hash)) continue;
			if (!block->confirmed) {
				debuglog("*** CONFIRMED %d : %s\n", block->height, block->hash2);
				strncpy(block->hash, blockhash, 65);
				block->confirmed = true;
			}
			return true;
		}
	}
	return false;
}
