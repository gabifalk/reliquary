/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Directly exercises seccomp_install(): a denied syscall (execve) must kill
   the process, and allowed syscalls must survive. The filter is installed only
   in short-lived forked children so the test harness itself stays unfiltered. */
#define _GNU_SOURCE
#include "seccomp.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* Exit codes the forked children use to report back to the parent. */
#define CHILD_SECCOMP_UNAVAIL 77	/* seccomp_install() returned -1     */
#define CHILD_EXECVE_RETURNED 42	/* execve ran (filter did not block) */

/* Install the filter, then attempt a denied syscall. If the filter works the
   kernel kills us before execve completes; reaching _exit means it did not. */
static void
child_execve_denied(void)
{
	if (seccomp_install() != 0)
		_exit(CHILD_SECCOMP_UNAVAIL);
	char *const argv[] = { (char *)"/bin/true", NULL };
	char *const envp[] = { NULL };
	execve("/bin/true", argv, envp);
	_exit(CHILD_EXECVE_RETURNED);
}

/* Install the filter, then touch only allowed syscalls and exit cleanly. */
static void
child_allowed_ok(void)
{
	if (seccomp_install() != 0)
		_exit(CHILD_SECCOMP_UNAVAIL);
	(void)getpid();
	(void)write(STDOUT_FILENO, "", 0);
	_exit(0);
}

/* Install the filter, then attempt a denied non-first denylist entry (socket).
   Guards against jump-offset bugs that would silently allow entries other than
   the first. Killed by the filter means blocked; _exit means it slipped through. */
static void
child_socket_denied(void)
{
	if (seccomp_install() != 0)
		_exit(CHILD_SECCOMP_UNAVAIL);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	(void)fd;
	_exit(CHILD_EXECVE_RETURNED);
}

static int
run_child(void (*fn)(void))
{
	pid_t pid = fork();
	if (pid == 0)
		fn();		/* never returns: always _exit()s */
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		exit(1);
	}
	return status;
}

int
main(void)
{
	printf("test_seccomp:\n");

	/* Preflight: if the filter can't be installed here at all, skip
	   (meson treats exit 77 as SKIP) instead of failing. */
	int pf = run_child(child_allowed_ok);
	if (WIFEXITED(pf) && WEXITSTATUS(pf) == CHILD_SECCOMP_UNAVAIL) {
		printf("  SKIP: seccomp unavailable on this kernel/arch\n");
		return 77;
	}

	printf("  allowed_syscalls_survive ... ");
	fflush(stdout);
	if (!(WIFEXITED(pf) && WEXITSTATUS(pf) == 0)) {
		printf("FAIL (raw status=%d)\n", pf);
		return 1;
	}
	printf("ok\n");

	printf("  execve_is_blocked ... ");
	fflush(stdout);
	int st = run_child(child_execve_denied);
	if (WIFEXITED(st) && WEXITSTATUS(st) == CHILD_EXECVE_RETURNED) {
		printf("FAIL: execve was not blocked by the filter\n");
		return 1;
	}
	if (!WIFSIGNALED(st)) {
		printf("FAIL: child not killed by a signal (raw status=%d)\n",
		       st);
		return 1;
	}
	printf("ok (killed by signal %d)\n", WTERMSIG(st));

	printf("  socket_is_blocked ... ");
	fflush(stdout);
	int ss = run_child(child_socket_denied);
	if (WIFEXITED(ss) && WEXITSTATUS(ss) == CHILD_EXECVE_RETURNED) {
		printf("FAIL: socket was not blocked by the filter\n");
		return 1;
	}
	if (!WIFSIGNALED(ss)) {
		printf("FAIL: child not killed by a signal (raw status=%d)\n",
		       ss);
		return 1;
	}
	printf("ok (killed by signal %d)\n", WTERMSIG(ss));

	printf("3/3 passed\n");
	return 0;
}
