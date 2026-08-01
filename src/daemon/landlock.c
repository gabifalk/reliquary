/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Hand-rolled Landlock filesystem confinement -- no liblandlock dependency, in
 * keeping with the rest of the project. See landlock.h for the contract.
 *
 * Landlock governs only the access rights a ruleset *handles*; anything handled
 * but not granted on some path is denied. We handle the read/write/create/
 * delete/rename rights and grant them on exactly the store subtree, so the
 * process keeps full access inside its own store and loses pathname access
 * everywhere else. Already-open descriptors (the listening socket, the client
 * connection, stderr) are unaffected -- Landlock is pathname-based.
 */
#define _GNU_SOURCE
#include "landlock.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__) && defined(__has_include)
# if __has_include(<linux/landlock.h>)
#  define RELIQUARY_HAVE_LANDLOCK 1
# endif
#endif

#ifdef RELIQUARY_HAVE_LANDLOCK
# include <stdint.h>
# include <string.h>
# include <errno.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/prctl.h>
# include <sys/syscall.h>
# include <linux/landlock.h>

# if !defined(__NR_landlock_create_ruleset) \
	|| !defined(__NR_landlock_add_rule) \
	|| !defined(__NR_landlock_restrict_self)
#  undef RELIQUARY_HAVE_LANDLOCK
# endif
#endif

#ifdef RELIQUARY_HAVE_LANDLOCK

/*
 * Rights added after ABI v1 -- absent from older uapi headers. Define them to
 * 0 so they drop out of the mask; the ABI check below also strips them when
 * the running kernel is too old.
 */
# ifndef LANDLOCK_ACCESS_FS_REFER
#  define LANDLOCK_ACCESS_FS_REFER 0
# endif
# ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#  define LANDLOCK_ACCESS_FS_TRUNCATE 0
# endif

/*
 * Everything the daemon legitimately does within its own store: read and
 * write key files, list dirs, create/remove token dirs and files, and the
 * temp-then-rename (REFER) that meta.c uses for atomic metadata writes.
 * fopen("wb") of an existing file truncates it, hence TRUNCATE.
 */
# define RELIQUARY_LL_FS ( \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE)

static int
ll_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
		  uint32_t flags)
{
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int
ll_add_rule(int ruleset_fd, enum landlock_rule_type type, const void *attr,
	    uint32_t flags)
{
	return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr,
			    flags);
}

static int
ll_restrict_self(int ruleset_fd, uint32_t flags)
{
	return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/*
 * Grant `access` on the subtree at `path`. A missing path is tolerated (the
 * grant is simply skipped) so optional device nodes do not fail the build of
 * the ruleset; any other error is fatal to confinement.
 */
static int
ll_grant(int ruleset_fd, const char *path, uint64_t access)
{
	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT) ? 0 : -1;

	struct landlock_path_beneath_attr pb;
	memset(&pb, 0, sizeof(pb));
	pb.allowed_access = access;
	pb.parent_fd = fd;

	int rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	close(fd);
	return rc;
}

int
landlock_confine(const char *path)
{
	if (getenv("RELIQUARY_SKIP_LANDLOCK")) {
		log_warn("WARNING: Landlock confinement bypassed via "
			 "RELIQUARY_SKIP_LANDLOCK (dev/test only)");
		return 0;
	}

	int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		return -1;	/* kernel < 5.13, or not in the LSM stack */

	uint64_t access = RELIQUARY_LL_FS;
	if (abi < 2)
		access &= ~(uint64_t)LANDLOCK_ACCESS_FS_REFER;
	if (abi < 3)
		access &= ~(uint64_t)LANDLOCK_ACCESS_FS_TRUNCATE;

	struct landlock_ruleset_attr rattr;
	memset(&rattr, 0, sizeof(rattr));
	rattr.handled_access_fs = access;

	int ruleset_fd = ll_create_ruleset(&rattr, sizeof(rattr), 0);
	if (ruleset_fd < 0)
		return -1;

	/* Full access within our own store subtree... */
	int rc = ll_grant(ruleset_fd, path, access);
	/*
	 * ...plus read-only access to the kernel RNG device files, which
	 * libgcrypt opens for entropy at operation time (it does not always
	 * use getrandom(2)). These are world-readable; granting read does not
	 * widen the store confinement. IOCTL_DEV is not a handled right, so
	 * libgcrypt's ioctls on them are unaffected.
	 */
	if (rc == 0)
		rc = ll_grant(ruleset_fd, "/dev/urandom",
			      LANDLOCK_ACCESS_FS_READ_FILE);
	if (rc == 0)
		rc = ll_grant(ruleset_fd, "/dev/random",
			      LANDLOCK_ACCESS_FS_READ_FILE);
	if (rc != 0) {
		close(ruleset_fd);
		return -1;
	}

	/*
	 * landlock_restrict_self() requires no-new-privs (or CAP_SYS_ADMIN);
	 * assert it here, idempotent with main.c, to stay self-contained.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		close(ruleset_fd);
		return -1;
	}
	rc = ll_restrict_self(ruleset_fd, 0);
	close(ruleset_fd);
	return rc == 0 ? 0 : -1;
}

#else /* !RELIQUARY_HAVE_LANDLOCK */

int
landlock_confine(const char *path)
{
	(void)path;
	if (getenv("RELIQUARY_SKIP_LANDLOCK")) {
		log_warn("WARNING: Landlock confinement bypassed via "
			 "RELIQUARY_SKIP_LANDLOCK (dev/test only)");
		return 0;
	}
	return -1;	/* no Landlock support compiled in for this target */
}

#endif
