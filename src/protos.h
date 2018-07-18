// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  protos.h - pwcheckd prototypes
 *  Copyright (C) 2007 SGDN
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */


#ifndef _PROTOS_H
#define _PROTOS_H

#define _GNU_SOURCE
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define PREFIX_MASTER	"master"

extern const char *g_prefix;

#define _WARN(fmt, args...) fprintf(stderr, "[%s] "fmt"\n", g_prefix, ##args)
#define _WARN_ERRNO(fmt, args...) \
	fprintf(stderr, "[%s] "fmt": %s\n", g_prefix, ##args, strerror(errno))
#define _LOG(fmt, args...) printf("[%s] "fmt"\n", g_prefix, ##args)
#define _DEBUG(fmt, args...) printf("[%s](%s) "fmt"\n",g_prefix, \
						__FUNCTION__, ##args)

#ifdef USE_SYSLOG

#define WARN(fmt, args...) do { \
	if (g_daemonized) \
		syslog(LOG_WARNING, "[%s] "fmt"\n", g_prefix, ##args); \
	else \
		_WARN(fmt, ##args); \
} while (0)

#define WARN_ERRNO(fmt, args...) do {\
	if (g_daemonized) \
		syslog(LOG_WARNING, "[%s] "fmt": %s\n", g_prefix, \
						##args, strerror(errno)); \
	else \
		_WARN_ERRNO(fmt, ##args); \
} while (0)

#define WARN_PAM(fmt, pamh, errnum, args...) do {\
	if (g_daemonized) \
		syslog(LOG_WARNING, "[%s] "fmt": pam error: %s\n", g_prefix, \
					##args, pam_strerror(pamh, errnum)); \
	else \
		_WARN(fmt ": pam error: %s", ##args, pam_strerror(pamh, errnum)); \
} while (0)

#define LOG(fmt, args...) do {\
	if (g_daemonized) \
		syslog(LOG_INFO, "[%s] "fmt"\n", g_prefix, ##args); \
	else \
		_LOG(fmt, ##args); \
} while (0)

#define DEBUG(fmt, args...) do {\
	if (g_verbose) {\
		if (g_daemonized) \
			syslog(LOG_DEBUG, "[%s](%s) "fmt"\n", g_prefix, \
							__FUNCTION__, ##args); \
		else \
			_DEBUG(fmt, ##args); \
	} \
} while (0)

#else /* ! USE_SYSLOG */

#define WARN _WARN

#define WARN_PAM(fmt, pamh, errnum, args...) \
		_WARN(fmt ": pam error: %s", ##args, pam_strerror(pamh, errnum))

#define WARN_ERRNO _WARN_ERRNO

#define LOG _LOG

#define DEBUG(fmt, args...) do {\
	if (g_verbose)\
		_DEBUG(fmt, ##args);\
} while (0)

#endif /* ! USE_SYSLOG */

int check_user_self(int sock, char *sockname);
int check_user_x11(int sock, char *sockname);

extern int g_daemonized;
extern int g_verbose;

#define __U __attribute__((unused))

#endif /* _PROTOS_H */
