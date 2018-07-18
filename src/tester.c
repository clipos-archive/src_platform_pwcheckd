// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#define PWLEN 64

#define WARN(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

#ifdef PWCHECKD_SOCKET
#define _PWCHECKD_SOCKET TO_STR(PWCHECKD_SOCKET)
#else
#define _PWCHECKD_SOCKET "/tmp/clip.sock"
#endif

static void
usage(const char *prog)
{
	printf("usage: %s <sock> <service|password>\n", prog);
}

static int
do_test(const char *sock, const char *service)
{
	char *ptr;
	struct sockaddr_un sau;
	ssize_t len;
	char c;
	int s, ret = -1;

	sau.sun_family = AF_UNIX;
	snprintf(sau.sun_path, sizeof(sau.sun_path), "%s", sock);
	
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return ret;
	}
	
	if (connect(s, (struct sockaddr *)&sau, sizeof(struct sockaddr_un)) < 0) {
		perror("connect");
		goto out;
	}
	
	len = write(s, service, strlen(service));
	if (len < 0) {
		perror("write");
		goto out;
	}	

	if (read(s, &c, 1) < 0) {
		perror("read");
		goto out;
	}

	if (c == 'Y')
		ret = 0;
out:
	close(s);
	return ret;
}

int 
main(int argc, char *argv[])
{
	if (argc < 3) {
		usage(basename(argv[0]));
		return EXIT_FAILURE;
	}

	return do_test(argv[1], argv[2]);
}
		
