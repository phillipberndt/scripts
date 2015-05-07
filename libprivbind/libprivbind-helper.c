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
	char *fd_str = getenv("SOCKET_FD");
	char *port_str = getenv("SOCKET_PORT");
	char *address = getenv("SOCKET_ADDRESS");

	if(!fd_str || !port_str || !address) {
		printf("This program is intended to be run from libprivbind.\n");
		exit(-1);
	}

	int fd = atoi(fd_str);
	int port = atoi(port_str);

	int is_suid = 0;
	if(getuid() != geteuid() && geteuid() == 0) {
		is_suid = 1;
		if(seteuid(getuid()) != 0) {
			exit(-6);
		}
	}

	int sock_domain;
	int sock_domain_length = sizeof(sock_domain);
	if(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &sock_domain, &sock_domain_length) != 0) {
		exit(-3);
	}
	if(sock_domain != AF_INET && sock_domain != AF_INET6) {
		exit(-3);
	}

	char grant_file[255];
	if(snprintf(grant_file, 255, "/etc/privbind/%d", port) > 255) {
		exit(-1);
	}
	if(access(grant_file, X_OK)) {
		exit(-2);
	}

	char port_reprint[7];
	if(snprintf(port_reprint, 7, "%d", port) > 7) {
		exit(-1);
	}

	struct addrinfo *address_info;
	struct addrinfo hints = { AI_PASSIVE, sock_domain, 0, 0, 0, NULL, NULL, NULL };
	int addrinfo_rv = getaddrinfo(address[0] == 0 ? NULL : address, port_reprint, &hints, &address_info);
	if(addrinfo_rv != 0) {
		exit(-4);
	}

	if(is_suid) {
		if(seteuid(0) != 0) {
			exit(errno);
		}
	}

	if(bind(fd, address_info->ai_addr, address_info->ai_addrlen) == 0) {
		freeaddrinfo(address_info);
		exit(0);
	}

	freeaddrinfo(address_info);
	if(errno == EACCES) {
		exit(-6);
	}
	exit(errno);
}
