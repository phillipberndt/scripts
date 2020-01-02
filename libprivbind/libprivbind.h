/**
 * Create sockets that are bound to privileged ports
 */

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

static int privbind(int sockfd, char *address, in_port_t port) {
	char fd_str[7];
	char port_str[7];
	int status = 0;

	/* Python 3 sets F_CLOEXEC */
	int fdflags = fcntl(sockfd, F_GETFD, NULL);
	fdflags &= ~FD_CLOEXEC;
	fcntl(sockfd, F_SETFD, fdflags);
	fdflags = fcntl(sockfd, F_GETFD, NULL);

	pid_t child_pid = fork();
	if(child_pid == 0) {
		snprintf(fd_str, 7, "%d", sockfd);
		snprintf(port_str, 7, "%d", port);

		setenv("SOCKET_FD", fd_str, 1);
		setenv("SOCKET_PORT", port_str, 1);
		setenv("SOCKET_ADDRESS", address, 1);
		execlp("libprivbind-helper", "libprivbind-helper", NULL);
		exit(-5);
	}

	waitpid(child_pid, &status, 0);
	if(!WIFEXITED(status)) {
		return 1;
	}
	return WEXITSTATUS(status);
}
