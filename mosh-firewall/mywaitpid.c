/*
 * int mywaitpid(pid_t)
 *
 * Wait for a non-child PID to exit. Linux specific, requires root permissions.
 *
 * Returns 1 on failure,
 * returns 0 on success & after the process has exited.
 *
 * This file is based on:
 *
 * Process/Thread Start Monitor
 * Copyright (C) 2011 Philip J. Turmel <philip@turmel.org>
 *
 * Inspired by a blog entry by Scott James Remnant:
 * http://netsplit.com/2011/02/09/the-proc-connector-and-socket-filters/
 *
 * Maintained at http://github.com/pturmel/startmon
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <alloca.h>

static pid_t netlink_exit_handler(struct nlmsghdr *nlhdr) {
	switch (nlhdr->nlmsg_type) {
		case NLMSG_ERROR:
		case NLMSG_NOOP:
		case NLMSG_OVERRUN:
			return getpid();
		default:
			1;
	}

	struct cn_msg *hdr = NLMSG_DATA(nlhdr);

	if (hdr->id.idx != CN_IDX_PROC || hdr->id.val != CN_VAL_PROC)
		return getpid();
	struct proc_event *pe = (struct proc_event *)hdr->data;
	if(pe->what == PROC_EVENT_EXIT) {
		return pe->event_data.exec.process_pid;
	}
}

int mywaitpid(pid_t pid) {
	pid_t my_pid;
	int bcount;

	if(kill(pid, 0) != 0)
		return 0;

	int nlsock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
	if(nlsock == -1)
		return 1;

	struct sockaddr_nl nladdr = {AF_NETLINK};
	socklen_t          nlalen;
	nladdr.nl_pid = my_pid = getpid();
	nladdr.nl_groups = CN_IDX_PROC;
	if(bind(nlsock, (struct sockaddr *)&nladdr, sizeof(nladdr))) {
		close(nlsock);
		return 1;
	}

	enum proc_cn_mcast_op cnop  = PROC_CN_MCAST_LISTEN;
	struct cn_msg         cnmsg = {{CN_IDX_PROC, CN_VAL_PROC}, 0, 0, sizeof(cnop), 0};
	struct nlmsghdr       nlmsg = {NLMSG_LENGTH(sizeof cnmsg + sizeof cnop), NLMSG_DONE};
	char padding[16];
	struct iovec iov[4] = {
		{&nlmsg, sizeof(nlmsg)},
		{padding, NLMSG_LENGTH(0) - sizeof(nlmsg)},
		{&cnmsg, sizeof(cnmsg)},
		{&cnop, sizeof(cnop)}
	};
	nlmsg.nlmsg_pid = my_pid;
	if((bcount = writev(nlsock, iov, 4)) == -1) {
		close(nlsock);
		return 1;
	}
	void *rcvbuf = alloca(4096+CONNECTOR_MAX_MSG_SIZE);
	if (!rcvbuf) {
		close(nlsock);
		return 1;
	}

	while (1) {
		int nlalen = sizeof(nladdr);
		bcount = recvfrom(nlsock, rcvbuf, 4096+CONNECTOR_MAX_MSG_SIZE, 0, (struct sockaddr *)&nladdr, &nlalen);
		if (nladdr.nl_pid == 0) {
			struct nlmsghdr *hdr = rcvbuf;
			for (hdr=rcvbuf; NLMSG_OK(hdr, bcount); hdr=NLMSG_NEXT(hdr, bcount)) {
				pid_t exited_pid = netlink_exit_handler(hdr);
				if(exited_pid != my_pid) {
					if(exited_pid == pid) {
						close(nlsock);
						return 0;
					}
				}
			}
		}
	}
}
