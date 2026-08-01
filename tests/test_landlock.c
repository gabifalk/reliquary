/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Exercises landlock_confine(): after confining to a directory, a write inside
   it must succeed and a write outside it must be denied. Run in a short-lived
   forked child so the (irrevocable) restriction does not affect the harness. */
#define _GNU_SOURCE
#include "landlock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Exit codes the child reports to the parent. */
#define CHILD_UNAVAIL       77	/* confinement not applied -> skip        */
#define CHILD_INSIDE_DENIED 41	/* a write inside the store was blocked   */
#define CHILD_OUTSIDE_OK    42	/* a write outside the store slipped past */

static char g_inside[512];
static char g_outside[512];

static void
child_confined(void)
{
	/* Never let the escape hatch mask a real confinement test. */
	unsetenv("RELIQUARY_SKIP_LANDLOCK");

	if (landlock_confine(g_inside) != 0)
		_exit(CHILD_UNAVAIL);

	char inpath[600];
	snprintf(inpath, sizeof(inpath), "%s/f", g_inside);
	int fd = open(inpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		_exit(CHILD_INSIDE_DENIED);
	close(fd);

	fd = open(g_outside, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		close(fd);
		_exit(CHILD_OUTSIDE_OK);
	}
	if (errno != EACCES && errno != EPERM)
		_exit(CHILD_OUTSIDE_OK);	/* denied, but not by the sandbox */

	_exit(0);			/* inside allowed, outside denied */
}

static int
run_child(void)
{
	pid_t pid = fork();
	if (pid == 0)
		child_confined();	/* never returns */
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
	printf("test_landlock:\n");

	char tmpl[] = "/tmp/test_landlock_XXXXXX";
	char *base = mkdtemp(tmpl);
	if (!base) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(g_inside, sizeof(g_inside), "%s/store", base);
	snprintf(g_outside, sizeof(g_outside), "%s/outside", base);
	if (mkdir(g_inside, 0700) != 0) {
		perror("mkdir");
		return 1;
	}

	int st = run_child();
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

	/* cleanup regardless of outcome */
	char inpath[600];
	snprintf(inpath, sizeof(inpath), "%s/f", g_inside);
	unlink(inpath);
	unlink(g_outside);
	rmdir(g_inside);
	rmdir(base);

	if (code == CHILD_UNAVAIL) {
		printf("  SKIP: Landlock unavailable on this kernel\n");
		return 77;
	}

	int fail = 0;

	printf("  write_inside_store_allowed ... ");
	if (code == CHILD_INSIDE_DENIED) {
		printf("FAIL: write inside the confined store was denied\n");
		fail = 1;
	} else {
		printf("ok\n");
	}

	printf("  write_outside_store_denied ... ");
	if (code == 0) {
		printf("ok\n");
	} else if (code == CHILD_OUTSIDE_OK) {
		printf("FAIL: write outside the confined store was allowed\n");
		fail = 1;
	} else if (code == CHILD_INSIDE_DENIED) {
		printf("skipped (inside check failed first)\n");
	} else {
		printf("FAIL: unexpected child status %d\n", code);
		fail = 1;
	}

	if (!fail)
		printf("2/2 passed\n");
	return fail;
}
