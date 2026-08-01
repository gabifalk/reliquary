/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE
#include "server.h"
#include "session.h"
#include "crypto.h"
#include "log.h"
#include <assuan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <poll.h>

static volatile sig_atomic_t got_sigchld = 0;

static void
sigchld_handler(int sig)
{
	(void)sig;
	got_sigchld = 1;
}

static void
reap_children(void)
{
	pid_t p;
	while ((p = waitpid(-1, NULL, WNOHANG)) > 0)
		log_debug("child pid=%d exited", (int)p);
	got_sigchld = 0;
}

/* Minimal sd_listen_fds: return the inherited socket fd or -1. */
static int
sd_listen_fd(void)
{
	const char *lp = getenv("LISTEN_PID");
	const char *lf = getenv("LISTEN_FDS");
	if (!lp || !lf)
		return -1;
	if ((pid_t)atoi(lp) != getpid())
		return -1;
	if (atoi(lf) < 1)
		return -1;
	return 3;		/* SD_LISTEN_FDS_START */
}

static int
create_socket(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	unlink(path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	chmod(path, 0700);

	if (listen(fd, 5) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static uid_t
get_peer_uid(int fd)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
		return cred.uid;
	return (uid_t)-1;	/* fail closed: never fall back to getuid() */
}

/* Refuse to run unless we are setgid to RELIQUARY_GROUP. */
static int
verify_setgid(void)
{
	/* An tescape hatch for the testsuite. */
	if (getenv("RELIQUARY_SKIP_SETGID_CHECK")) {
		log_warn("WARNING: setgid self-check bypassed via "
			"RELIQUARY_SKIP_SETGID_CHECK (dev/test only)");
		return 0;
	}

	struct group *g = getgrnam(RELIQUARY_GROUP);
	if (!g) {
		log_error("group '%s' does not exist; cannot verify setgid; "
			  "refusing to start", RELIQUARY_GROUP);
		return -1;
	}
	if (getegid() != g->gr_gid || getegid() == getgid()) {
		log_error("not running setgid '%s' (egid=%u gid=%u); "
			  "refusing to start.", RELIQUARY_GROUP,
			  (unsigned)getegid(), (unsigned)getgid());
		return -1;
	}
	return 0;
}

static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [--store PATH]\n", prog);
	fprintf(stderr, "\nSocket: $XDG_RUNTIME_DIR/reliquary/socket\n");
	fprintf(stderr, "Store:  %s/<uid>/  (override with --store)\n",
		DEFAULT_STORE);
}

int
main(int argc, char **argv)
{
	const char *store_override = NULL;
	int verbosity = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbosity++;
		} else if (strcmp(argv[i], "-vv") == 0) {
			verbosity += 2;
		} else if (strcmp(argv[i], "--store") == 0 && i + 1 < argc)
			store_override = argv[++i];
		else if (strcmp(argv[i], "--help") == 0
			 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	const char *dbg = getenv("RELIQUARY_DEBUG");
	int env_level = dbg ? atoi(dbg) : 0;
	log_init(verbosity > env_level ? verbosity : env_level);

	const char *xdg = getenv("XDG_RUNTIME_DIR");
	if (!xdg) {
		log_error("$XDG_RUNTIME_DIR is not set");
		return 1;
	}

	if (verify_setgid() != 0)
		return 1;

	/* Key files and token dirs must be owner-only (0600/0700). */
	umask(0077);

	char socket_dir[256], socket_path[280];
	snprintf(socket_dir, sizeof(socket_dir), "%s/reliquary", xdg);
	snprintf(socket_path, sizeof(socket_path), "%s/socket", socket_dir);
	mkdir(socket_dir, 0700);

	if (crypto_init() != 0) {
		log_error("failed to initialize crypto");
		return 1;
	}

	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	int listen_fd = sd_listen_fd();
	int activated = (listen_fd >= 0);
	if (!activated) {
		listen_fd = create_socket(socket_path);
		if (listen_fd < 0) {
			log_error("cannot create socket at %s: %s",
				socket_path, strerror(errno));
			return 1;
		}
	}

	/*
	 * The store we serve is fixed for this daemon's lifetime -- our own uid's
	 * subtree (getuid()), or the --store override. Compute it once here so it
	 * can be reused by every child.
	 */
	char store_root[512];
	if (store_override) {
		strncpy(store_root, store_override, sizeof(store_root) - 1);
		store_root[sizeof(store_root) - 1] = '\0';
	} else {
		snprintf(store_root, sizeof(store_root), "%s/%u",
			 DEFAULT_STORE, (unsigned)getuid());
	}

	log_debug("listening on %s%s", socket_path,
		activated ? " (socket-activated)" : "");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &sa, NULL);

	while (1) {
		if (got_sigchld)
			reap_children();

		struct pollfd pfd = { .fd = listen_fd, .events = POLLIN };
		int pr = poll(&pfd, 1, -1);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			log_error("poll: %s", strerror(errno));
			continue;
		}

		int client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			log_error("accept: %s", strerror(errno));
			continue;
		}

		uid_t peer_uid = get_peer_uid(client_fd);

		if (peer_uid == (uid_t)-1) {
			log_warn("SO_PEERCRED failed; rejecting connection");
			close(client_fd);
			continue;
		}

		if (peer_uid != getuid()) {
			log_warn("peer uid %u is not the store owner %u; "
				"rejecting connection", (unsigned)peer_uid,
				(unsigned)getuid());
			close(client_fd);
			continue;
		}

		log_debug("connection accepted: peer uid=%u",
			(unsigned)peer_uid);

		pid_t pid = fork();
		if (pid < 0) {
			log_error("fork: %s", strerror(errno));
			close(client_fd);
			continue;
		}
		if (pid > 0) {
			log_debug("forked child pid=%d", (int)pid);
			close(client_fd);
			continue;
		}

		close(listen_fd);

		/*
		 * store_root was computed above from getuid() (or --store) and
		 * is inherited across fork; the daemon only ever serves the
		 * account it runs as (peer_uid == getuid() is enforced above).
		 */
		session_t sess;
		session_init(&sess, peer_uid, store_root);

		assuan_context_t srv_ctx;
		if (server_init(&srv_ctx, client_fd, &sess) != 0)
			_exit(1);

		server_run(srv_ctx);
		assuan_release(srv_ctx);
		session_destroy(&sess);
		_exit(0);
	}

	return 0;
}
