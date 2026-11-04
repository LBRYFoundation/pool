#include "stratum.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

bool socket_connected(YAAMP_SOCKET *s)
{
	return s->sock > 0;
}

void socket_real_ip(YAAMP_SOCKET *s)
{
	// get real ip if we are using haproxy or similar that use PROXY protocol
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	int size, ret;
	const char v2sig[] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

	do {
		ret = recv(s->sock, &hdr, sizeof(hdr), MSG_PEEK);
	} while (ret == -1 && errno == EINTR);

	if (ret >= (16 + ntohs(hdr.v2.len)) &&
		memcmp(&hdr.v2, v2sig, 12) == 0 &&
		((hdr.v2.ver_cmd & 0xF0) == 0x20) &&
		hdr.v2.fam == 0x11) {
		// we received a proxy v2 header
		inet_ntop(AF_INET, &hdr.v2.addr.ip4.src_addr, s->ip, 64);
		s->port = ntohs(hdr.v2.addr.ip4.src_port);

		size = 16 + ntohs(hdr.v2.len);
		do {
			ret = recv(s->sock, &hdr, size, 0);
		} while (ret == -1 && errno == EINTR);
		return;
	}
	else {
		struct sockaddr_in name;
		socklen_t len = sizeof(name);
		memset(&name, 0, len);

		int res = getpeername(s->sock, (struct sockaddr *)&name, &len);
		(void)res;
		inet_ntop(AF_INET, &name.sin_addr, s->ip, 64);

		res = getsockname(s->sock, (struct sockaddr *)&name, &len);
		s->port = ntohs(name.sin_port);
		return;
	}
}

YAAMP_SOCKET *socket_initialize(int sock)
{
	struct timeval timeout;
	timeout.tv_sec = g_socket_recv_timeout;
	timeout.tv_usec = 0;
	YAAMP_SOCKET *s = new YAAMP_SOCKET;
	memset(s, 0, sizeof(YAAMP_SOCKET));

	s->buflen = 0;
	s->sock = sock;

	setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
	int set = 1;
	setsockopt(s->sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif

	if (!g_handle_haproxy_ips) {
		int res = 0;
		struct sockaddr_in name;
		socklen_t len = sizeof(name);
		memset(&name, 0, len);

		res = getpeername(s->sock, (struct sockaddr *)&name, &len);
		(void)res;
		inet_ntop(AF_INET, &name.sin_addr, s->ip, 64);

		res = getsockname(s->sock, (struct sockaddr *)&name, &len);
		s->port = ntohs(name.sin_port);
	} else {
		socket_real_ip(s);
	}

	return s;
}

void socket_close(YAAMP_SOCKET *s)
{
	if (g_debuglog_socket) {
		debuglog("socket_close\n");
	}

	if(!s) return;
	if(s->sock) close(s->sock);

	s->sock = 0;
	delete s;
}

json_value *socket_nextjson(YAAMP_SOCKET *s, YAAMP_CLIENT *client)
{
	while(!strchr(s->buffer, '}') && s->buflen<YAAMP_SOCKET_BUFSIZE-1)
	{
		int len = recv(s->sock, s->buffer+s->buflen, YAAMP_SOCKET_BUFSIZE-s->buflen-1, 0);
		if(len <= 0) return NULL;

		s->last_read = time(NULL);
		s->total_read += len;

		s->buflen += len;
		s->buffer[s->buflen] = 0;

		if(client && client->logtraffic)
			stratumlog("recv: %d\n", s->buflen);
	}

	char *b = strchr(s->buffer, '{');
	if(!b)
	{
		if(client)
			clientlog(client, "bad json");

		debuglog("%s\n", s->buffer);
		return NULL;
	}

	char *p = strchr(b, '}');
	if (p) {
		if(!strchr(p, '{')) p = strrchr(b, '}');
		else { p = strchr(p, '{'); p--; }
	}

	if(!p)
	{
		if(client)
			clientlog(client, "bad json end");

		debuglog("%s\n", b);
		return NULL;
	}

	p++;

	char saved = *p;
	*p = 0;

	if(client && client->logtraffic)
		stratumlog("%s, %s, %s, %s, recv: %s\n", client->sock->ip, client->username, client->password, g_current_algo->name, s->buffer);

	int bytes = strlen(b);

	json_value *json = json_parse(b, bytes);
	if(!json)
	{
		if(client)
			clientlog(client, "bad json parse");

		debuglog("%s\n", b);
		return NULL;
	}

	*p = saved;
	while(*p && *p != '{')
		p++;

	if(*p == '{')
	{
		memmove(s->buffer, p, s->buflen - (p - s->buffer));

		s->buflen = s->buflen - (p - s->buffer);
		s->buffer[s->buflen] = 0;
	}
	else
	{
		memset(s->buffer, 0, YAAMP_SOCKET_BUFSIZE);
		s->buflen = 0;
	}

	return json;
}

int socket_send_raw(YAAMP_SOCKET *s, const char *buffer, int size)
{
	if (g_debuglog_socket) {
		debuglog("socket send: %s", buffer);
	}

	int res = send(s->sock, buffer, size, MSG_NOSIGNAL);
	return res;
}

int socket_send(YAAMP_SOCKET *s, const char *format, ...)
{
	char buffer[YAAMP_SMALLBUFSIZE];
	va_list args;

	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	if(!s) {
		errno = EINVAL;
		return -1;
	}

	int res = socket_send_raw(s, buffer, strlen(buffer));
	return res;
}
