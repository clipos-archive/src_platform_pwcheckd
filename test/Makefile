# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2007-2018 ANSSI. All Rights Reserved.
CFLAGS += -I../src

all: checker request timeout

checker: checker.c ../src/checker.c
	$(CC) -o $@ $< -lpam -lclip

request: request.c
	$(CC) -o $@ $<

timeout: timeout.c
	$(CC) -o $@ $<

clean:
	rm -f checker request timeout

