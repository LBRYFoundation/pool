#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Usage: blocknotify [-p password] server:port coinid blockhash
// Also supports STRATUM_PASSWORD environment variable (defaults to "tu8tu5")

int main(int argc, char **argv)
{
	const char *password = getenv("STRATUM_PASSWORD");
	if (!password || !password[0]) {
		password = "tu8tu5";
	}

	int arg_offset = 1;
	if (argc >= 6 && strcmp(argv[1], "-p") == 0) {
		password = argv[2];
		arg_offset = 3;
	}

	if (argc - arg_offset < 3)
	{
		printf("usage: blocknotify [-p password] server:port coinid blockhash\n");
		return 1;
	}

	char target[256] = { 0 };
	snprintf(target, sizeof(target), "%s", argv[arg_offset]);

	char *p = strchr(target, ':');
	if (!p)
	{
		printf("usage: blocknotify [-p password] server:port coinid blockhash\n");
		return 1;
	}

	*p = '\0';
	const char *host = target;
	const char *port_str = p + 1;

	int coinid = atoi(argv[arg_offset + 1]);
	char blockhash[256] = { 0 };
	snprintf(blockhash, sizeof(blockhash), "%s", argv[arg_offset + 2]);

	struct addrinfo hints, *res_info = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port_str, &hints, &res_info) != 0 || !res_info)
	{
		printf("error resolving host %s:%s id %d\n", host, port_str, coinid);
		return 1;
	}

	int sock = socket(res_info->ai_family, res_info->ai_socktype, res_info->ai_protocol);
	if (sock < 0)
	{
		printf("error socket %s:%s id %d\n", host, port_str, coinid);
		freeaddrinfo(res_info);
		return 1;
	}

	int res = connect(sock, res_info->ai_addr, res_info->ai_addrlen);
	freeaddrinfo(res_info);
	if (res < 0)
	{
		printf("error connect %s:%s id %d\n", host, port_str, coinid);
		close(sock);
		return 1;
	}

	char buffer[1024];
	int len = snprintf(buffer, sizeof(buffer),
		"{\"id\":1,\"method\":\"mining.update_block\",\"params\":[\"%s\",%d,\"%s\"]}\n",
		password, coinid, blockhash);

	if (len > 0 && len < (int)sizeof(buffer)) {
		send(sock, buffer, (size_t)len, 0);
	}
	close(sock);

	return 0;
}
