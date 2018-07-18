// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static int usage (const char *);

static int usage(const char *s)
{
	fprintf(stderr, "Usage: %s <path to socket>\n", s);
	return 1;
}

int main(int argc, const char *argv[])
{
	int s;
	char c;
	struct sockaddr_un sau;
	ssize_t len;

	if (argc != 2)
		exit(usage(argv[0]));

	sau.sun_family = AF_UNIX;
	snprintf(sau.sun_path, sizeof(sau.sun_path), 
		"%s", argv[1]);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return 1;
	}
	
	if (connect(s, (struct sockaddr *)&sau, sizeof(struct sockaddr_un)) < 0) {
		perror("connect");
		close(s);
		return 1;
	}
	
	for (;;)
		sleep(1);
}
