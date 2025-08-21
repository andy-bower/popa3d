/*
 * Standalone POP server: accepts connections, checks the anti-flood limits,
 * logs and starts the actual POP sessions.
 */

#include "params.h"

#if POP_STANDALONE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if DAEMON_LIBWRAP
#include <tcpd.h>
int allow_severity = SYSLOG_PRI_LO;
int deny_severity = SYSLOG_PRI_HI;
#endif

/*
 * These are defined in pop_root.c.
 */
extern int log_error(char *s);
extern int do_pop_startup(void);
extern int do_pop_session(void);
extern int af;

typedef volatile sig_atomic_t va_int;

/*
 * Active POP sessions.  Those that were started within the last MIN_DELAY
 * seconds are also considered active (regardless of their actual state),
 * to allow for limiting the logging rate without throwing away critical
 * information about sessions that we could have allowed to proceed.
 */
static struct {
	char addr[NI_MAXHOST];		/* Source IP address */
	volatile int pid;		/* PID of the server, or 0 for none */
	clock_t start;			/* When the server was started */
	clock_t log;			/* When we've last logged a failure */
} sessions[MAX_SESSIONS];

static va_int child_blocked;		/* We use blocking to avoid races */
static va_int child_pending;		/* Are any dead children waiting? */

/*
 * SIGCHLD handler.
 */
static void handle_child(int signum)
{
	int saved_errno;
	int pid;
	int i;

	saved_errno = errno;

	if (child_blocked)
		child_pending = 1;
	else {
		child_pending = 0;

		while ((pid = waitpid(0, NULL, WNOHANG)) > 0)
		for (i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].pid == pid) {
			sessions[i].pid = 0;
			break;
		}
	}

	signal(SIGCHLD, handle_child);

	errno = saved_errno;
}

#if DAEMON_LIBWRAP
static void check_access(int sock)
{
	struct request_info request;

	request_init(&request,
		RQ_DAEMON, DAEMON_LIBWRAP_IDENT,
		RQ_FILE, sock,
		0);
	fromhost(&request);

	if (!hosts_access(&request)) {
/* refuse() shouldn't return... */
		refuse(&request);
/* ...but just in case */
		exit(1);
	}
}
#endif

#if POP_OPTIONS
int do_standalone(void)
#else
int main(void)
#endif
{
	int true = 1;
	int sock, new;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int pid;
	struct tms buf;
	clock_t min_delay, now, log;
	int i, j, n;
	struct addrinfo hints, *res;
	char hbuf[NI_MAXHOST];
	char sbuf[NI_MAXSERV];
	int error;

	if (do_pop_startup()) return 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		return log_error("socket");

	snprintf(sbuf, sizeof(sbuf), "%u", DAEMON_PORT);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, sbuf, &hints, &res);
	if (error)
		return log_error("getaddrinfo");

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0) {
		freeaddrinfo(res);
		return log_error("socket");
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (void *)&true, sizeof(true))) {
		freeaddrinfo(res);
		return log_error("setsockopt");
	}

#ifdef IPV6_V6ONLY
	if (res->ai_family == AF_INET6 && setsockopt(sock, IPPROTO_IPV6,
	    IPV6_V6ONLY, (void *)&true, sizeof(true))) {
		freeaddrinfo(res);
		return log_error("setsockopt");
	}
#endif

	if (bind(sock, res->ai_addr, res->ai_addrlen)) {
		freeaddrinfo(res);
		return log_error("bind");
	}
	freeaddrinfo(res);

	if (listen(sock, MAX_BACKLOG))
		return log_error("listen");

	chdir("/");
	setsid();

	switch (fork()) {
	case -1:
		return log_error("fork");

	case 0:
		break;

	default:
		return 0;
	}

	setsid();

#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	min_delay = MIN_DELAY * sysconf(_SC_CLK_TCK);
#else
	min_delay = MIN_DELAY * CLK_TCK;
#endif

	child_blocked = 1;
	child_pending = 0;
	signal(SIGCHLD, handle_child);

	memset((void *)sessions, 0, sizeof(sessions));
	log = 0;

	new = 0;

	while (1) {
		child_blocked = 0;
		if (child_pending) raise(SIGCHLD);

		if (new > 0)
		if (close(new)) return log_error("close");

		addrlen = sizeof(addr);
		new = accept(sock, (struct sockaddr *)&addr, &addrlen);

		error = getnameinfo((struct sockaddr *)&addr, addrlen,
		    hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
		if (error)
			; /* XXX */


/*
 * I wish there were a portable way to classify errno's...  In this case,
 * it appears to be better to risk eating up the CPU on a fatal error
 * rather than risk terminating the entire service because of a minor
 * temporary error having to do with one particular connection attempt.
 */
		if (new < 0) continue;

		now = times(&buf);
		if (!now) now = 1;

		child_blocked = 1;

		j = -1; n = 0;
		for (i = 0; i < MAX_SESSIONS; i++) {
			if (sessions[i].start > now)
				sessions[i].start = 0;
			if (sessions[i].pid ||
			    (sessions[i].start &&
			    now - sessions[i].start < min_delay)) {
				if (strcmp(sessions[i].addr, hbuf) == 0)
					if (++n >= MAX_SESSIONS_PER_SOURCE)
						break;
			} else
			if (j < 0) j = i;
		}

		if (n >= MAX_SESSIONS_PER_SOURCE) {
			if (!sessions[i].log ||
			    now < sessions[i].log ||
			    now - sessions[i].log >= min_delay) {
				syslog(SYSLOG_PRI_HI,
					"%s: per source limit reached",
					hbuf);
				sessions[i].log = now;
			}
			continue;
		}

		if (j < 0) {
			if (!log ||
			    now < log || now - log >= min_delay) {
				syslog(SYSLOG_PRI_HI,
					"%s: sessions limit reached",
					hbuf);
				log = now;
			}
			continue;
		}

		switch ((pid = fork())) {
		case -1:
			syslog(SYSLOG_PRI_ERROR, "%s: fork: %m", hbuf);
			break;

		case 0:
			if (close(sock)) return log_error("close");
#if DAEMON_LIBWRAP
			check_access(new);
#endif
			syslog(SYSLOG_PRI_LO, "Session from %s",
				hbuf);
			if (dup2(new, 0) < 0) return log_error("dup2");
			if (dup2(new, 1) < 0) return log_error("dup2");
			if (dup2(new, 2) < 0) return log_error("dup2");
			if (close(new)) return log_error("close");
			return do_pop_session();

		default:
			strlcpy(sessions[j].addr, hbuf,
				sizeof(sessions[j].addr));
			sessions[j].pid = pid;
			sessions[j].start = now;
			sessions[j].log = 0;
		}
	}
}

#endif
