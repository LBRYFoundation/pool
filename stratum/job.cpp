#include "stratum.h"

#define RETURN_ON_CONDITION(condition, ret) \
	if(condition) \
	{ \
		return ret; \
	}

static bool job_assign_client(YAAMP_JOB *job, YAAMP_CLIENT *client, double maxhash)
{
	RETURN_ON_CONDITION(client->deleted, true);
	RETURN_ON_CONDITION(client->jobid_next, true);
	RETURN_ON_CONDITION(client->jobid_locked && client->jobid_locked != job->id, true);
	RETURN_ON_CONDITION(client_find_job_history(client, job->id), true);
	RETURN_ON_CONDITION(maxhash > 0 && job->speed + client->speed > maxhash, true);

	if(!g_autoexchange && maxhash >= 0. && client->coinid != job->coind->id) {
		return true;
	}

	strcpy(client->extranonce1, client->extranonce1_default);
	client->extranonce2size = client->extranonce2size_default;
	client->jobid_locked = 0;
	client->jobid_next = job->id;

	job->speed += client->speed;
	job->count++;

	if(strcmp(client->extranonce1, client->extranonce1_last) || client->extranonce2size != client->extranonce2size_last)
	{
		if(!client->extranonce_subscribe)
		{
			strcpy(client->extranonce1_reconnect, client->extranonce1);
			client->extranonce2size_reconnect = client->extranonce2size;

			strcpy(client->extranonce1, client->extranonce1_default);
			client->extranonce2size = client->extranonce2size_default;

			client->reconnecting = true;
			client->lock_count++;
			client->unlock = true;
			client->jobid_sent = client->jobid_next;

			socket_send(client->sock, "{\"id\":null,\"method\":\"client.reconnect\",\"params\":[\"%s\",%d,0]}\n", g_tcp_server, g_tcp_port);
		}
		else
		{
			strcpy(client->extranonce1_last, client->extranonce1);
			client->extranonce2size_last = client->extranonce2size;

			socket_send(client->sock, "{\"id\":null,\"method\":\"mining.set_extranonce\",\"params\":[\"%s\",%d]}\n",
				client->extranonce1, client->extranonce2size);
		}
	}

	return true;
}

void job_assign_clients(YAAMP_JOB *job, double maxhash)
{
	if (!job) return;

	job->speed = 0;
	job->count = 0;

	g_list_client.Enter();

	// pass0 locked
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_locked && client->jobid_locked != job->id) continue;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	// pass1 sent
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_sent != job->id) continue;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	// pass2 the rest
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	g_list_client.Leave();
}

void job_assign_clients_left(double factor)
{
	bool b;
	for(CLI li = g_list_coind.first; li; li = li->next)
	{
		if(!job_has_free_client()) return;

		YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
		if(!coind_can_mine(coind)) continue;
		if(!coind->job) continue;

		double nethash = coind_nethash(coind);
		g_list_client.Enter();

		for(CLI li = g_list_client.first; li; li = li->next)
		{
			YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
			if (!g_autoexchange) {
				if (client->coinid == coind->id)
					factor = 100.;
				else
					factor = 0.;
			}

			if (factor > 0.) {
				b = job_assign_client(coind->job, client, nethash*factor);
				if(!b) break;
			}
		}

		g_list_client.Leave();
	}
}

////////////////////////////////////////////////////////////////////////

pthread_mutex_t g_job_mutex;
pthread_cond_t g_job_cond;

void *job_thread(void *p)
{
	CommonLock(&g_job_mutex);
	while(!g_exiting)
	{
		job_update();
		pthread_cond_wait(&g_job_cond, &g_job_mutex);
	}
	return NULL;
}

void job_init()
{
	pthread_mutex_init(&g_job_mutex, 0);
	pthread_cond_init(&g_job_cond, 0);

	pthread_t thread3;
	pthread_create(&thread3, NULL, job_thread, NULL);
}

void job_signal()
{
	CommonLock(&g_job_mutex);
	pthread_cond_signal(&g_job_cond);
	CommonUnlock(&g_job_mutex);
}

void job_update()
{
	job_reset_clients();

	//////////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_job.Enter();
	job_sort();

	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_assign_clients(job, job->maxspeed);
		job_unlock_clients(job);

		if(!job_has_free_client()) break;
	}

	job_unlock_clients();
	g_list_job.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_coind.Enter();
	coind_sort();

	job_assign_clients_left(1);
	job_assign_clients_left(1);
	job_assign_clients_left(-1);

	g_list_coind.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(client->jobid_next) continue;

		debuglog("clients with no job\n");
		g_current_algo->overflow = true;

		if(!g_list_coind.first) break;

		YAAMP_COIND *coind = (YAAMP_COIND *)g_list_coind.first->data;
		if(!coind) break;

		job_reset_clients(coind->job);
		coind_create_job(coind, true);
		job_assign_clients(coind->job, -1);

		break;
	}

	g_list_client.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_broadcast(job);
	}

	g_list_job.Leave();
}
