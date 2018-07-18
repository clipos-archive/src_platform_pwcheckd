// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* Nyark nyark */

#include "../src/checker.c"

int 
main(int argc, char *argv[])
{
	struct auth_info auth;
	int ret;
	uid_t uid;

	if (argc < 4) {
		puts("Usage : checker <username> <passwd> <uid>");
		return EXIT_FAILURE;
	}
	
	auth.username = argv[1];
	auth.passwd = argv[2];
	uid = atoi(argv[3]);

	if (setuid(uid)) {
		perror("setuid");
		return EXIT_FAILURE;
	}

	ret = do_auth(&auth);

	if (ret)
		puts("failure");
	else
		puts("success");
	return ret;
}
