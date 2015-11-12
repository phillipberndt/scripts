/*
	A wrapper for mosh-server that opens a port in the firewall for the mosh
	connection.

	Copyright (c) 2015, Phillip Berndt <phillip.berndt@gmail.com>
	Available under the terms & conditions of the GPL v3.


	Note: 
	
	This program has two security relevant race conditions. It uses kill (signal 0) to
	check if mosh is still running in 2 second intervals. Another process might start
	right after mosh quit and reuse the pid. This program would not realize this.
	Also, since it only checks every 2 seconds, another program might reuse the port
	mosh-server used right after mosh quit. Since most setups contain a conntrack rule
	that allows existing connections to continue, any connection opened within this
	two second window would persist.

	To install:

	dpkg-divert --add --rename --divert /usr/bin/mosh-server-real /usr/bin/mosh-server
	gcc -std=c99 -o /usr/bin/mosh-server mosh-server-firewall.c
	chown root:root /usr/bin/mosh-server
	chmod u+s /usr/bin/mosh-server

*/
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	int pipefd[2];
	pipe(pipefd);
	int epipefd[2];
	pipe(epipefd);

	int cpid = fork();
	if(cpid == 0) {
		// Run the real mosh-server as the original user,
		// redirecting stdout/stderr into pipes

		setresuid(getuid(), getuid(), getuid());
		setresgid(getgid(), getgid(), getgid());
		setpgid(0, 0);
		close(1);
		close(2);
		close(pipefd[0]);
		close(epipefd[0]);
		dup2(pipefd[1], 1);
		dup2(epipefd[1], 2);

		execv("/usr/bin/mosh-server-real", argv);
		return 1;
	}
	close(pipefd[1]);
	close(epipefd[1]);
	clearenv();

	// Mosh-server outputs "\nMOSH CONNECT <port> <key>\n" on stdout.
	// Capture & extract port
	char std_input[1024];
	int std_data_len;
	std_data_len = read(pipefd[0], std_input, sizeof(std_input));
	std_input[std_data_len] = 0;
	char *port_pos = strstr(std_input, "MOSH CONNECT ");
	if(!port_pos) {
		return 0;
	}
	int port = atoi(port_pos + sizeof("MOSH CONNECT ") - 1);

	// it furthermore prints some stuff on stderr, including its pid
	// in a string "pid = <pid>". Capture that as well.
	char *pid_pos = 0;
	char input[10240];
	int input_pos = 0;
	int data_len;
	while(!pid_pos) {
		data_len = read(epipefd[0], &input[input_pos], sizeof(input) - input_pos);
		if(!data_len) return 0;
		input_pos += data_len;
		input[input_pos] = 0;
		pid_pos = strstr(input, "pid = ");
	}
	int pid = atoi(pid_pos + sizeof("pid = ") - 1);

	// Reading finished, wait for the child process
	wait(NULL);

	if(fork() == 0) {
		// Fork a subprocess that takes care of the iptables rules required for mosh-server
		// Detach it further to prevent ssh from killing it as the pty is closed
		setpgid(0, 0);
		setsid();
		daemon(0, 0);

		char sport[10];
		char comment[30];
		sprintf(sport, "%d", port);
		sprintf(comment, "Added for mosh pid %d", pid);

		if(fork() == 0) {
			execl("/sbin/iptables", "/sbin/iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", sport, "-j", "ACCEPT", "-m", "comment", "--comment", comment, NULL);
		}
		wait(NULL);

		// pid is not a child process, so use this technique to check if it is still alive
		while(kill(pid, 0) == 0) {
			sleep(2);
		}

		if(fork() == 0) {
			execl("/sbin/iptables", "/sbin/iptables", "-D", "INPUT", "-p", "udp", "--dport", sport, "-j", "ACCEPT", "-m", "comment", "--comment", comment, NULL);
		}
		wait(NULL);

		return 0;
	}
	wait(NULL);

	// Now output the data. We could not have done this earlier, because mosh closes the ssh connection right after it received the
	// stdout lines, and this kills this process.
	write(1, std_input, std_data_len);
	write(2, input, data_len);
}
