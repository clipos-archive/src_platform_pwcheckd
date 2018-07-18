// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  checker.c - pwcheckd authentication functions
 *  Copyright (C) 2007 SGDN
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */


#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/wait.h>

#include <security/pam_appl.h>
#include <clip/clip.h>

#include "protos.h"

#define PW_MAXLEN 64
#define PW_TRIES  1

#define PW_TIMEOUT_DEFAULT	25
#ifndef PW_TIMEOUT
#define PW_TIMEOUT	PW_TIMEOUT_DEFAULT
#endif

#define X11_TIMEOUT_DEFAULT	60
#ifndef X11_TIMEOUT
#define X11_TIMEOUT	X11_TIMEOUT_DEFAULT
#endif

#define PW_READ_TIMEOUT (PW_TIMEOUT * 500) /* msecs */

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

#define X11_SCRIPT TO_STR(SBINDIR)"/pwcheck_x11"
#define X11_SEP "\r\n"

struct auth_info {
	char *username;
	char *passwd;
};

#ifdef USE_TCB

#ifdef TCB_GROUP
#define _TCB_GROUP TO_STR(TCB_GROUP)
#else
#define _TCB_GROUP "shadow"
#endif 

static int
set_gid(void)
{
	const struct group *grp = getgrnam(_TCB_GROUP);
	if (!grp) {
		WARN_ERRNO("could not get gid for group %s", _TCB_GROUP);
		return -1;
	}

	if (setgid(grp->gr_gid)) {
		WARN_ERRNO("could not set gid to %d(%s)", 
					grp->gr_gid, _TCB_GROUP);
		return -1;
	}

	return 0;
}

#endif /* ! USE_TCB */


/*************************************************************/
/*                   Common PAM part                         */
/*************************************************************/

static int
conversation(int num_msg, const struct pam_message **msg, 
		struct pam_response **resp, void *data)
{
	int i;
	struct pam_response *reply;
	char *pwd;
	
	const struct auth_info *auth = data;

	reply = malloc(num_msg * sizeof(*reply));
	if (!reply)
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) 
		reply[i].resp = NULL;
	
	for (i = 0; i < num_msg; i++) {
	    switch (msg[i]->msg_style) {
	        /* Ignore those */
	        case PAM_TEXT_INFO:
	        	reply[i].resp_retcode = PAM_SUCCESS;
	        	break;
	        case PAM_PROMPT_ECHO_OFF:
	        	pwd = strdup(auth->passwd);
	        	if (!pwd)
	        		goto out_free;
	        	reply[i].resp = pwd;
	        	reply[i].resp_retcode = PAM_SUCCESS;
	        	break;
	        /* We don't expect this, since we already gave the username
	         * to pam, but let's play it safe... */
	        case PAM_PROMPT_ECHO_ON:
	        	pwd = strdup(auth->username);
	        	if (!pwd)
	        		goto out_free;
	        	reply[i].resp = pwd;
	        	reply[i].resp_retcode = PAM_SUCCESS;
	        	break;
	        default:
	        	goto out_free;
	    }
	}
		
	*resp = reply;
	return PAM_SUCCESS;
			
out_free:
	for (i = 0; i < num_msg; i++) {
		if (reply[i].resp)
			free(reply[i].resp);
	}
	free(reply);
	return PAM_CONV_ERR;
}

static int
do_auth(struct auth_info *auth)
{
	int error;
	pam_handle_t *pamh;

	int ret = -1;
	struct pam_conv conv = {
		.conv = conversation,
		.appdata_ptr = auth,
	};

	error = pam_start("pwcheckd", auth->username, &conv, &pamh);
	if (error != PAM_SUCCESS) {
		WARN_PAM("could not start PAM", pamh, error);
		goto end_pam;
	}

	error = pam_authenticate(pamh, 0);
	if (error != PAM_SUCCESS) {
		WARN_PAM("could not authenticate", pamh, error);
		goto end_pam;
	}

	error = pam_acct_mgmt(pamh, 0);
	if (error != PAM_SUCCESS) {
		WARN_PAM("account management error", pamh, error);
		goto end_pam;
	}

	ret = 0;
	
end_pam:
	error = pam_end(pamh, error);
	if (error != PAM_SUCCESS) {
		WARN_PAM("could not end pam session", pamh, error);
		return -1;
	}

	return ret;
}

/*************************************************************/
/*                   Signal handling                         */
/*************************************************************/

static void 
sigalrm_action(int signum, siginfo_t *info, void *ctx __U)
{
	if (signum != SIGALRM) {
		WARN("Unexpected signal %d, expected SIGALRM", signum);
		return;
	}
	if (info->si_code != SI_KERNEL) {
		WARN("Received SIGALRM from unexpected source : %d:%d:%d",
				info->si_code, info->si_pid, info->si_uid);
		 
		return;
	}

	WARN("Authentication timer expired, aborting authentication");
	exit(EXIT_FAILURE);
}

static void 
sigpipe_action(int signum, siginfo_t *info, void *ctx __U)
{
	if (signum != SIGPIPE) {
		WARN("Unexpected signal %d, expected SIGPIPE", signum);
		return;
	}
	if (info->si_code != SI_USER || info->si_pid != getpid()) {
		WARN("Received SIGALRM from unexpected source : %d:%d:%d",
				info->si_code, info->si_pid, info->si_uid);
		return;
	}
	WARN("Client socket closed, aborting");
	exit(EXIT_FAILURE);
}


static int
install_sigactions(void)
{
	struct sigaction alrm_action = {
		.sa_sigaction = sigalrm_action,
		.sa_flags = SA_SIGINFO | SA_RESETHAND,
		.sa_restorer = NULL,
	};
	struct sigaction pipe_action = {
		.sa_sigaction = sigpipe_action,
		.sa_flags = SA_SIGINFO | SA_RESETHAND,
		.sa_restorer = NULL,
	};
	sigemptyset(&alrm_action.sa_mask);
	sigemptyset(&pipe_action.sa_mask);

	if (sigaction(SIGALRM, &alrm_action, NULL))
		return -1;
	if (sigaction(SIGPIPE, &pipe_action, NULL))
		return -1;
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
		return -1;
	return 0;
}


/*************************************************************/
/*                   'Self' type sockets                     */
/*************************************************************/

static char *
get_passwd(int s)
{
	char buf[PW_MAXLEN];
	ssize_t readlen;
	char *ret;

	readlen = clip_sock_read(s, buf, PW_MAXLEN, PW_READ_TIMEOUT, PW_TRIES);
	/* We don't deal with EINTR, etc... */
	if (readlen < 0) {
		WARN_ERRNO("could not read password");
		return NULL;
	}


	if (readlen == PW_MAXLEN) {
		WARN("password is too long\n");
		return NULL;
	}

	buf[readlen] = '\0';
	
	ret = strdup(buf);
	if (!ret) 
		WARN_ERRNO("could not copy password");

	return ret;
}

static int 
do_ack(int s, int retval)
{
	char c = (retval) ? 'N' : 'Y';

	if (write(s, &c, 1) != 1) {
		WARN_ERRNO("could not write ack");
		(void)close(s);
		return -1;
	}
	(void)close(s);
	return 0;
}

int 
check_user_self(int s, char *sockname __U)
{
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;
	char *tmp;
	int ret;

	struct auth_info auth;

#ifdef USE_SYSLOG
	/* Reopen syslog in 'auth' facility */
	if (g_daemonized)
		openlog("pwcheckd", LOG_PID, LOG_AUTH);
#endif

	if (install_sigactions()) {
		WARN("could no install signal handlers");
		return -1;
	}

	if (alarm(PW_TIMEOUT)) 
		WARN("resetting previous timer");

	if (clip_getpeereid(s, &uid, &gid)) {
		WARN("could not get peer creds");
		return -1;
	}

#ifdef USE_TCB
	if (set_gid())
		return -1;

	if (setuid(uid)) {
		WARN_ERRNO("setuid failed");
		return -1;
	}
#endif

	pwd = getpwuid(uid);
	if (!pwd) {
		WARN_ERRNO("user not found");
		return -1;
	}

	tmp = strdup(pwd->pw_name);
	if (!tmp) {
		WARN("out of memory?\n");
		return -1;
	}
	auth.username = tmp;

	tmp = get_passwd(s);
	if (!tmp) {
		free(auth.username);
		return -1;
	}
	auth.passwd = tmp;

	ret = do_auth(&auth);

	if (ret)
		LOG("Authentication failure for %s", auth.username);
	else
		LOG("Successful authentication for %s", auth.username);

	free(auth.passwd);
	free(auth.username);

	ret |= do_ack(s, ret);
	return ret;
}
/*************************************************************/
/*                   'X11' type sockets                      */
/*************************************************************/

static int
run_x11_cmd(int fd, char *service, char *sockname)
{
	int ret;
	char tmp[sizeof(X11_SCRIPT)] = X11_SCRIPT;
	char *const argv[] = { tmp, service, sockname, NULL };
	char *envp[] = { NULL };

	(void)close(STDOUT_FILENO);
	
	if (dup2(fd, STDOUT_FILENO) == -1) {
		WARN_ERRNO("dup2() failed");
		return -1;
	}

	ret = -execve(argv[0], argv, envp);
	if (ret) 
		WARN("X11 command %s - %s failed: %d", X11_SCRIPT, 
							service, ret);
	return ret;
}

static int
read_child_auth(int fd, struct auth_info *auth) {
	char buf[2*PW_MAXLEN + 3];
	size_t len;
	ssize_t rret;
	char *endptr, *pwptr;

	rret = read(fd, buf, sizeof(buf));
	if (rret < 0) {
		WARN_ERRNO("read() failed");
		return -1;
	}
	len = rret;
	if (!len) {
		WARN("Unexpected EOF");
		return -1;
	}
	if (len == sizeof(buf)) {
		WARN("Password + username too long");
		return -1;
	}
	buf[len] = '\0';

	endptr = strstr(buf, X11_SEP);
	if (!endptr) {
		WARN("Wrong response from child");
		return -1;
	}
	if ((size_t)(endptr - buf) >= 
			(size_t)(len + 1 - sizeof(X11_SEP))) {
		WARN("Empty password");
		return -1;
	}
	pwptr = endptr + sizeof(X11_SEP) - 1;

	auth->username = strndup(buf, endptr - buf);
	if (!auth->username) {
		WARN("Out of memory for username");
		return -1;
	}
	auth->passwd = strdup(pwptr);
	if (!auth->passwd) {
		WARN("Out of memory for password");
		free(auth->username);
		return -1;
	}
	LOG("Current X11 user is %s", auth->username);

	return 0;
}

static int 
get_x11_auth(struct auth_info *auth, char *service, char *sockname)
{
	int fds[2];
	pid_t pid, wret;
	int status;

	if (pipe(fds)) {
		WARN_ERRNO("pipe() failed");
		return -1;
	}

	pid = fork();
	switch (pid) {
		case -1:
			WARN_ERRNO("fork() failed");
			return -1;
		case 0:
			(void)close(fds[0]);
			exit(run_x11_cmd(fds[1], service, sockname));
		default:
			(void)close(fds[1]);
			wret = waitpid(pid, &status, 0);
			if (wret < 0) {
				WARN_ERRNO("waitpid() X11 failed");
				return -1;
			}
			if (wret != pid) {
				WARN("waitpid() returned wrong child: %d != %d",
						wret, pid);
				return -1;
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				WARN("Abnormal child termination");
				return -1;
			}

			if (read_child_auth(fds[0], auth))
				return -1;
			return 0;
	}
			
	WARN("Not reached!");
	return -1;
}

int
check_user_x11(int s, char *sockname)
{
	int ret;

	struct auth_info auth;
	char service[PW_MAXLEN + 1];
	ssize_t rret;
	size_t len;

#ifdef USE_SYSLOG
	/* Reopen syslog in 'auth' facility */
	if (g_daemonized)
		openlog("pwcheckd", LOG_PID, LOG_AUTH);
#endif

	if (install_sigactions()) {
		WARN("could no install signal handlers");
		return -1;
	}

	if (alarm(X11_TIMEOUT)) 
		WARN("resetting previous timer");


	rret = read(s, service, sizeof(service));
	if (rret < 0) {
		WARN_ERRNO("read() service failed");
		return -1;
	}
	len = rret;
	if (!len) {
		WARN("Unexpected EOF while reading service name");
		return -1;
	}
	if (len == sizeof(service)) {
		WARN("Service name too long");
		return -1;
	}
	service[len] = '\0';

	if (get_x11_auth(&auth, service, sockname))
		return -1;

	ret = do_auth(&auth);

	if (ret)
		LOG("Authentication failure for %s", auth.username);
	else
		LOG("Successful authentication for %s", auth.username);

	free(auth.passwd);
	free(auth.username);

	ret |= do_ack(s, ret);
	return ret;
}
