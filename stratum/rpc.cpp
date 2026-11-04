#include "stratum.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

bool rpc_connected(YAAMP_RPC *rpc)
{
	return rpc->sock > 0;
}

bool rpc_connect(YAAMP_RPC *rpc)
{
	rpc_close(rpc);
	if(g_exiting) return false;

	struct addrinfo hints, *res_info = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", rpc->port);

	if(getaddrinfo(rpc->host, port_str, &hints, &res_info) != 0 || !res_info)
		return false;

	rpc->sock = socket(res_info->ai_family, res_info->ai_socktype, res_info->ai_protocol);
	if(rpc->sock <= 0) {
		freeaddrinfo(res_info);
		return false;
	}

	int res = connect(rpc->sock, res_info->ai_addr, res_info->ai_addrlen);
	freeaddrinfo(res_info);
	if(res < 0)
	{
		rpc_close(rpc);
		return false;
	}

	yaamp_create_mutex(&rpc->mutex);
	rpc->id = 0;
	rpc->bufpos = 0;

	if (g_debuglog_rpc) {
		debuglog("connected to %s:%d\n", rpc->host, rpc->port);
	}

	return true;
}

void rpc_close(YAAMP_RPC *rpc)
{
	if(!rpc_connected(rpc)) return;
	pthread_mutex_destroy(&rpc->mutex);

	close(rpc->sock);
	rpc->sock = 0;

	if (g_debuglog_rpc) {
		debuglog("disconnected from %s:%d\n", rpc->host, rpc->port);
	}
}

///////////////////////////////////////////////////////////////////

int rpc_send_raw(YAAMP_RPC *rpc, const char *buffer, int bytes)
{
	if(!rpc_connected(rpc)) return -1;

	int res = send(rpc->sock, buffer, bytes, MSG_NOSIGNAL);
	if(res <= 0) return res;

	if (g_debuglog_rpc) {
		debuglog("sending >%s<\n", buffer);
	}

	return res;
}

int rpc_flush_soft(YAAMP_RPC *rpc)
{
	if(!rpc_connected(rpc)) return -1;

	int res = send(rpc->sock, rpc->buffer, rpc->bufpos, MSG_MORE);
	rpc->bufpos = 0;

	return res;
}

int rpc_flush(YAAMP_RPC *rpc)
{
	if(!rpc_connected(rpc)) return -1;

	int res = rpc_send_raw(rpc, rpc->buffer, rpc->bufpos);
	rpc->bufpos = 0;

	return res;
}

int rpc_send(YAAMP_RPC *rpc, const char *format, ...)
{
	if(!rpc_connected(rpc)) return -1;

	char buffer[YAAMP_SMALLBUFSIZE] = { 0 };
	va_list args;

	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	int bytes = strlen(buffer);
	if(bytes + rpc->bufpos > YAAMP_SMALLBUFSIZE)
		return -1;

	memcpy(rpc->buffer + rpc->bufpos, buffer, bytes);
	rpc->bufpos += bytes;

	return bytes;
}

/////////////////////////////////////////////////////////////////////////////////

char *rpc_do_call(YAAMP_RPC *rpc, char const *data)
{
	CommonLock(&rpc->mutex);

	rpc_send(rpc, "POST / HTTP/1.1\r\n");
	rpc_send(rpc, "Authorization: Basic %s\r\n", rpc->credential);
	rpc_send(rpc, "Host: %s:%d\n", rpc->host, rpc->port);
	rpc_send(rpc, "Accept: */*\r\n");
	rpc_send(rpc, "Content-Type: application/json\r\n");
	rpc_send(rpc, "Content-Length: %zu\r\n\r\n", strlen(data));

	int res = rpc_flush(rpc);
	if(res <= 0)
	{
		CommonUnlock(&rpc->mutex);
		return NULL;
	}

	res = rpc_send_raw(rpc, data, strlen(data));
	if(res <= 0)
	{
		CommonUnlock(&rpc->mutex);
		return NULL;
	}

	int bufpos = 0;
	char buffer[YAAMP_SMALLBUFSIZE] = { 0 };

	while(!g_exiting)
	{
		int bytes = recv(rpc->sock, buffer+bufpos, YAAMP_SMALLBUFSIZE-bufpos-1, 0);
		if (g_debuglog_rpc) {
			debuglog("got %s\n", buffer+bufpos);
		}
		if(bytes <= 0)
		{
			debuglog("ERROR: recv1, %d, %d, %s, %s\n", bytes, errno, data, buffer);
			CommonUnlock(&rpc->mutex);
			return NULL;
		}

		bufpos += bytes;
		buffer[bufpos] = 0;

		if(strstr(buffer, "\r\n\r\n")) break;
	}

	///////////////////////////////////////////////////

	const char *p = strchr(buffer, ' ');
	if(!p)
	{
		CommonUnlock(&rpc->mutex);
		return NULL;
	}

	int status = atoi(p+1);
	if(status != 200)
		debuglog("ERROR: rpc_do_call: %s:%d %d\n", rpc->host, rpc->port, status);

	char tmp[1024];

	header_value(buffer, "Transfer-Encoding:", tmp);
	if (!strcmp(tmp, "chunked")) {
#ifdef HAVE_CURL
		if (!rpc->curl) debuglog("%s chunked transfer detected, switching to curl!\n",
			rpc->coind->symbol);
		rpc->curl = 1;
#endif
		CommonUnlock(&rpc->mutex);
		rpc_connect(rpc);
		return NULL;
	}

	int datalen = atoi(header_value(buffer, "Content-Length:", tmp));
	if(!datalen)
	{
		debuglog("ERROR: rpc No Content-Length header!\n");
		CommonUnlock(&rpc->mutex);
		return NULL;
	}

	p = strstr(buffer, "\r\n\r\n");
	bufpos = strlen(p+4);

	char *databuf = (char *)malloc(datalen+1);
	if(!databuf)
	{
		CommonUnlock(&rpc->mutex);
		return NULL;
	}

	memcpy(databuf, p+4, bufpos+1);

	while(bufpos < datalen)
	{
		int bytes = recv(rpc->sock, databuf+bufpos, datalen-bufpos, 0);
		if(bytes <= 0)
		{
			debuglog("ERROR: recv2, %d, %d, %s\n", bytes, errno, data);
			rpc_connect(rpc);

			free(databuf);
			CommonUnlock(&rpc->mutex);
			return NULL;
		}

		bufpos += bytes;
		databuf[bufpos] = 0;
	}

	CommonUnlock(&rpc->mutex);

	header_value(buffer, "Connection:", tmp);
	if(strcmp(tmp, "close") == 0)
	{
		rpc_connect(rpc);
	}

	return databuf;
}

json_value *rpc_call(YAAMP_RPC *rpc, char const *method, char const *params)
{
#ifdef HAVE_CURL
	if (rpc->ssl || rpc->curl)
		return rpc_curl_call(rpc, method, params);
#endif

	long long s1 = current_timestamp();
	if(!rpc_connected(rpc)) return NULL;

	int paramlen = params ? strlen(params) : 0;

	char *message = (char *)malloc(paramlen+1024);
	if(!message) return NULL;

	if(params)
		snprintf(message, paramlen+1024, "{\"method\":\"%s\",\"params\":%s,\"id\":\"%d\"}", method, params, ++rpc->id);
	else
		snprintf(message, paramlen+1024, "{\"method\":\"%s\",\"id\":\"%d\"}", method, ++rpc->id);

	char *buffer = rpc_do_call(rpc, message);

	free(message);
	if(!buffer) return NULL;

	json_value *json = json_parse(buffer, strlen(buffer));
	if(!json) {
		debuglog("invalid json: %s", buffer);
		free(buffer);
		return NULL;
	}
	free(buffer);

	long long s2 = current_timestamp();
	if(s2-s1 > 2000)
		debuglog("delay rpc_call %s:%d %s in %lld ms\n", rpc->host, rpc->port, method, s2-s1);

	if(json->type != json_object)
	{
		json_value_free(json);
		return NULL;
	}

	return json;
}
