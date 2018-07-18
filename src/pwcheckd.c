// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  pwcheckd.c - pwcheckd daemon 
 *  Copyright (C) 2007 SGDN
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */


#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>

#include <clip/clip.h>

#include "protos.h"

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

/* Max number of childs per socket */
#define SOCK_MAX_CHILDS	4

int g_daemonized = 0;
int g_verbose = 0;

const char *g_prefix = PREFIX_MASTER;

static clip_sock_t *g_socks = NULL;
static size_t g_sock_num = 0;

static void
print_help(const char *prog)
{
	printf("%s [-hvVF] -s <name1>:<type1>:<path1> [ -s <nameN>:<typeN>:<pathN> ]+\n", prog);
	puts("Options:");
	puts("\t-h: print this help and exit");
	puts("\t-v: print the version number and exit");
	puts("\t-V: be more verbose in log messages");
	puts("\t-F: run in foreground (do not detach)");
	puts("\t-s <name>:<type>:<path>: listen on <path> as a type <type> socket named <name>");
}

static inline void
print_version(const char *prog)
{
	printf("%s - Version %s\n", prog, TO_STR(VERSION));
}

/*************************************************************/
/*                   Socket management                       */
/*************************************************************/

/* 
 * Socket types.
 */
typedef enum {
	SockTypeSelf = 1,
	SockTypeX11 = 2,
	SockTypeLast,
} sock_type_t;

typedef struct sock_info {
	pid_t childs[SOCK_MAX_CHILDS];
	sock_type_t type;
} sock_info_t;

static int
parse_sock_type(const char *str, size_t len, sock_type_t *type)
{
	if (!strncmp(str, "self", len)) {
		*type = SockTypeSelf;
		return 0;
	}
	if (!strncmp(str, "x11", len)) {
		*type = SockTypeX11;
		return 0;
	}
	/*  %.* is an int (4 bytes), but size_t can be 8 bytes, for example on amd64
	 *  (not that it makes sense to print INT_MAX chars)
	 */
	if (len > INT_MAX)
		len = INT_MAX;

	WARN("Unsupported socket type: %.*s", (int) len, str);
	return -1;
}

static int
add_sock(const char *arg)
{
	const char *name, *path, *type;
	size_t nlen, tlen, plen;
	clip_sock_t *new, *tmp;
	sock_info_t *info;
	sock_type_t sock_type;

	name = arg;
	plen = strlen(arg);

	type = strchr(arg, ':');
	if (!type) {
		WARN("invalid socket path: %s", arg);
		return -1;
	}
	nlen = type - arg;
	if (!nlen) {
		WARN("empty socket name: %s", arg);
		return -1;
	}
	type += 1;
	
	path = strchr(type, ':');
	if (!path) {
		WARN("invalid socket path: %s", arg);
		return -1;
	}
	tlen = path - type;
	if (!tlen) {
		WARN("empty socket type: %s", arg);
		return -1;
	}
	path += 1;

	plen -= nlen + tlen + 2;

	if (parse_sock_type(type, tlen, &sock_type))
		return -1;

	tmp = realloc(g_socks, (g_sock_num + 1) * sizeof(*g_socks));
	if (!tmp) {
		WARN("out of memory");
		return -1;
	}
	g_socks = tmp;
	new = g_socks + g_sock_num;
	g_sock_num++;
	memset(new, 0, sizeof(*new));
	new->sock = -1;

	new->name = strndup(name, nlen);
	new->path = strndup(path, plen);
	if (!new->name || !new->path) {
		WARN("out of memory");
		goto out_free;
	}
	info = malloc(sizeof(sock_info_t));
	if (!info) {
		WARN("out of memory");
		goto out_free;
	}
	memset(info, 0, sizeof(sock_info_t));
	info->type = sock_type; 
	new->private = info;

	return 0;

out_free:
	if (new->name) free(new->name);
	if (new->path) free(new->path);
	g_sock_num--; /* No point reallocing() it */
	return -1;
}

static void
free_socks(void)
{
	unsigned int i;
	clip_sock_t *iter;
	for (i = 0; i < g_sock_num; i++) {
		iter = g_socks + i; 
		if (iter->sock != -1)
			(void)close(iter->sock);
		if (iter->name)
			free(iter->name);
		if (iter->path)
			free(iter->path);
		if (iter->private)
			free(iter->private);
	}
	free(g_socks);
}

static int conn_handler(int, clip_sock_t *);

static int
bind_socks(void)
{
	unsigned int i;
	int s;
	clip_sock_t *iter;
	for (i = 0; i < g_sock_num; i++) {
		iter = g_socks + i; 
		if (iter->sock != -1) {
			WARN("Socket %s is already bound", iter->name);
			return -1;
		}
		s = clip_sock_listen(iter->path, &(iter->sau), 0);
		if (s < 0) {
			WARN_ERRNO("could not bind socket %s to %s", 
					iter->name, iter->path);
			return -1;
		}
		DEBUG("Listening for %s on %s", iter->name, iter->path);
		iter->sock = s;
		iter->handler = conn_handler;
	}
	return 0;
}

/*************************************************************/
/*                   Child management                        */
/*************************************************************/

static inline int
begin_child_protect(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &set, NULL)) {
		WARN("Failed to mask SIGCHLD");
		return -1;
	}
	return 0;
} 

static inline int
end_child_protect(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &set, NULL)) {
		WARN("Failed to unmask SIGCHLD");
		return -1;
	}
	return 0;
} 

/* Called under child protect */
static inline pid_t *
get_free_slot(pid_t slots[SOCK_MAX_CHILDS])
{
	unsigned int i;

	for (i = 0; i < SOCK_MAX_CHILDS; i++) {
		if (!slots[i])
			return slots + i;
	}
	return NULL;
}

/* Called in SIGCHLD handler, SIGCHLD blocked */
static void
unregister_child(pid_t pid)
{
	clip_sock_t *sock;
	pid_t *childs;
	unsigned int i, j;

	for (i = 0; i < g_sock_num; i++) {
		sock = g_socks + i;
		childs = sock->private;
		for (j = 0; j < SOCK_MAX_CHILDS; j++) {
			if (childs[j] == pid) {
				childs[j] = 0;
				DEBUG("Unregistered child %d for %s socket",
						pid, sock->name);
				return;
			}
		}
	}
	WARN("Failed to unregister unknown child %d", pid);
}

static void 
sigchld_action(int signum, siginfo_t *info, void *ctx __U)
{
	int status;
	if (signum != SIGCHLD) {
		WARN("Unexpected signal %d for pid %d", signum, info->si_pid);
		return;
	}
	switch (info->si_code) {
		case CLD_EXITED:
			break;
		case CLD_KILLED:
			WARN("Child %d got killed", info->si_pid);
			break;
		default:
			WARN("Unexpected SIGCHLD origin for %d: %d",
					info->si_pid, info->si_code);
			return;
	}

	if (waitpid(info->si_pid, &status, WNOHANG) != info->si_pid)
		WARN("Waitpid %d failed\n", info->si_pid);

	unregister_child(info->si_pid);
}

static int
install_sigchld_action(void)
{
	struct sigaction action = {
		.sa_sigaction = sigchld_action,
		.sa_flags = SA_NOCLDSTOP | SA_SIGINFO,
		.sa_restorer = NULL,
	};
	sigemptyset(&action.sa_mask);

	return (sigaction(SIGCHLD, &action, NULL));
}

static void run_sock(int, clip_sock_t *) __attribute__((noreturn));

static void
run_sock(int s, clip_sock_t *sock)
{
	sock_info_t *info = sock->private;

	switch (info->type) {
		case SockTypeSelf:
			LOG("Self authentication check on %s socket", 
								sock->name);
			exit(check_user_self(s, sock->name));
			break;
		case SockTypeX11:
			LOG("X11 authentication check on %s socket", 
								sock->name);
			exit(check_user_x11(s, sock->name));
			break;
		default:
			WARN("Invalid socket type %d on socket %s",
						info->type, sock->name);
			exit(EXIT_FAILURE);
	}
}

static int 
conn_handler(int s, clip_sock_t *sock)
{
	pid_t pid, *slot;

	DEBUG("got a connection in %s", sock->name);

	if (begin_child_protect())
		return -1;
	slot = get_free_slot(sock->private);
	if (!slot) {
		WARN("refusing connection on %s socket: "
			"too many active childs", sock->name);
		(void)end_child_protect();
		(void)close(s);
		return -1;
	}
	pid = fork();
	switch (pid) {
		case 0:
			(void)end_child_protect();
			(void)close(sock->sock);
#ifdef USE_SYSLOG
			/* Close 'daemon' log facily, prior to
			 * reopening 'auth' facility */
			if (g_daemonized)
				closelog();
#endif
			g_prefix = sock->name;
			run_sock(s, sock);
			break;
		case -1:
			WARN_ERRNO("fork");
			(void)end_child_protect();
			(void)close(s);
			return -1;
		default:
			(void)close(s);
			*slot = pid;
			DEBUG("registered connection pid %d for socket %s",
					pid, sock->name);
			(void)end_child_protect();
			return 0;
	}
}

static void
main_loop(void)
{
	for (;;) {
		if (clip_accept_one(g_socks, g_sock_num, 1)) {
			WARN("Failed to accept a connection");
		}
	}
	/* Not reached */
}

int 
main(int argc, char *argv[])
{
	int c;
	int daemonize = 1;
	
	while ((c = getopt(argc, argv, "FhvVs:")) != -1) {
		switch (c) {
			case 'F':
				daemonize = 0;
				break;
			case 'h':
				print_help(basename(argv[0]));
				return EXIT_SUCCESS;
			case 'v':
				print_version(basename(argv[0]));
				return EXIT_SUCCESS;
			case 'V':
				g_verbose++;
				break;
			case 's':
				if (add_sock(optarg)) {
					WARN("failed to add listener for %s"
						", aborting", optarg);
					goto out;
				}
				break;
			default:
				fprintf(stderr, "Unsupported option: -%c", c);
				return EXIT_FAILURE;
		}
	}

	if (daemonize) { 
		if (clip_daemonize()) {		
			WARN_ERRNO("could not daemonize");
			goto out;
		}
#ifdef USE_SYSLOG
		openlog("pwcheckd", LOG_PID, LOG_DAEMON);
#endif
		g_daemonized = 1;
	}

	if (install_sigchld_action()) {
		WARN("failed to register SIGCHLD handler");
		goto out;
	}
	
	if (bind_socks()) {
		WARN("could not bind all sockets, aborting");
		goto out;
	}

	main_loop();

	/* Not reached */
	WARN("came out of wait_loop()!");

out:
	free_socks();
	return EXIT_FAILURE;
}
