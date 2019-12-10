#include <fcntl.h>
#include <linux/watchdog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define GUARD(x) ({ int rv; rv = x; if(rv < 0) {perror(#x); abort();} rv; })
int fd = -1;

void sighandler(int signo) {
	if(fd > -1) {
		printf("Normal shut down. Disconnecting watchdog.\n");
		fflush(stdout);
		GUARD(write(fd, "V", 1));
		fsync(fd);
		close(fd);
	}
	signal(signo, SIG_DFL);
	raise(signo);
}

int main() {
	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGABRT, sighandler);

	int timeout;
	fd = GUARD(open("/dev/watchdog", O_RDWR));
	GUARD(ioctl(fd, WDIOC_GETTIMEOUT, &timeout));
	if(timeout < 6) {
		timeout = 6;
		GUARD(ioctl(fd, WDIOC_SETTIMEOUT, &timeout));
		printf("Timeout was too small. Set to 6s\n");
	}
	printf("Watchdog started, timeout is %d\n", timeout);
	fflush(stdout);

	timeout -= 5;

	while(1) {
		GUARD(ioctl(fd, WDIOC_KEEPALIVE, 0));
		sleep(timeout);
	}
}
