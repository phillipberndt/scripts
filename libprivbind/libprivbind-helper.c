#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

struct sockaddr_in addr;

int main() {
	char port_reprint[6];
	char *fd_str = getenv("SOCKET_FD");
	char *port_str = getenv("SOCKET_PORT");
	char *address = getenv("SOCKET_ADDRESS");

	if(!fd_str || !port_str) {
		printf("This program is intended to be run from libprivbind.\n");
		exit(-1);
	}

	int fd = atoi(fd_str);
	int port = atoi(port_str);

	char grant_file[255];
	if(snprintf(grant_file, 255, "/etc/privbind/%d", port) > 255) {
		exit(-1);
	}
	if(access(grant_file, X_OK)) {
		exit(-2);
	}

	snprintf(port_reprint, 6, "%d", port);
	struct addrinfo *address_info;
	if(getaddrinfo(address, port_reprint, NULL, &address_info) != 0) {
		exit(-1);
	}

	if(bind(fd, address_info->ai_addr, address_info->ai_addrlen) == 0) {
		freeaddrinfo(address_info);
		exit(0);
	}

	freeaddrinfo(address_info);
	exit(errno);
}
