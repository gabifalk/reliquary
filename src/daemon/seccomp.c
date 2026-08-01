/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * A hand-rolled classic-BPF seccomp denylist -- no libseccomp dependency, in
 * keeping with the rest of the project. See seccomp.h for the contract. The
 * filter is a denylist (default ALLOW) rather than an allowlist so a libc or
 * libgcrypt update that reaches for a new benign syscall does not SIGSYS the
 * daemon; it targets syscalls that are never legitimate here after startup.
 */
#define _GNU_SOURCE
#include "seccomp.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

/*
 * Detect a usable seccomp environment at compile time. Requires the Linux
 * uapi headers and an architecture whose syscall numbers we can vouch for.
 */
#if defined(__linux__) && defined(__has_include)
# if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) \
	&& __has_include(<linux/audit.h>)
#  if defined(__x86_64__) || defined(__aarch64__)
#   define RELIQUARY_HAVE_SECCOMP 1
#  endif
# endif
#endif

#ifdef RELIQUARY_HAVE_SECCOMP
# include <stddef.h>
# include <linux/audit.h>
# include <linux/filter.h>
# include <linux/seccomp.h>
# include <sys/syscall.h>

# if defined(__x86_64__)
#  define RELIQUARY_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define RELIQUARY_X32 1	/* x86_64 exposes the x32 ABI via a nr bit */
# elif defined(__aarch64__)
#  define RELIQUARY_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define RELIQUARY_X32 0
# endif

/*
 * Older uapi headers predate KILL_PROCESS; a kernel that does not recognise
 * the value falls back to the more severe interpretation of an unknown
 * action (thread kill), which is still lethal -- acceptable degradation.
 */
# ifndef SECCOMP_RET_KILL_PROCESS
#  define SECCOMP_RET_KILL_PROCESS 0x80000000U
# endif

/*
 * Syscalls neither the accept loop nor a connection child needs after startup.
 * NB: clone/openat/sendmsg/recvmsg are deliberately absent -- the parent forks
 * children, children open key files, and libassuan does fd I/O over the
 * already-connected socket. All of these exist on both supported arches.
 */
static const int denylist[] = {
	__NR_execve, __NR_execveat,	/* no exec: no shell, no new programs */
	__NR_socket, __NR_connect,	/* no new/outbound sockets           */
	__NR_ptrace,			/* no debugger attach                */
	__NR_process_vm_readv, __NR_process_vm_writev,
	__NR_userfaultfd, __NR_bpf, __NR_open_by_handle_at,
	__NR_keyctl, __NR_add_key, __NR_request_key,
	__NR_setns, __NR_unshare, __NR_mount, __NR_umount2,
	__NR_pivot_root, __NR_chroot,
	__NR_kexec_load, __NR_kexec_file_load,
	__NR_init_module, __NR_finit_module, __NR_delete_module,
};

int
seccomp_install(void)
{
	if (getenv("RELIQUARY_SKIP_SECCOMP")) {
		log_warn("WARNING: seccomp filter bypassed via RELIQUARY_SKIP_SECCOMP "
			 "(dev/test only)");
		return 0;
	}

	const size_t ndeny = sizeof(denylist) / sizeof(denylist[0]);
	const size_t extra = RELIQUARY_X32 ? 1 : 0;

	/*
	 * Layout (indices):
	 *   0        load seccomp_data.arch
	 *   1        arch == ours ? continue : KILL
	 *   2        load seccomp_data.nr
	 *  [3        (x86_64 only) nr has x32 bit set ? KILL : continue]
	 *   3+extra  .. deny checks: nr == denylist[k] ? KILL : continue
	 *   ..       RET ALLOW
	 *   kill_idx RET KILL
	 * Forward jumps target kill_idx; offsets are relative to the next
	 * instruction, so a jump at index i uses (kill_idx - (i + 1)).
	 */
	const size_t kill_idx = ndeny + extra + 4;
	struct sock_filter *f = calloc(kill_idx + 1, sizeof(*f));
	if (!f)
		return -1;

	/*
	 * Emit each instruction at an explicit index; the jump-offset reads of
	 * `i` must stay in their own statements, never in an `f[i++] = ...`
	 * subscript (that would leave the i++ and the offset read unsequenced).
	 * A forward jump at index i to kill_idx uses offset kill_idx-(i+1).
	 */
	size_t i = 0;
	f[i] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		offsetof(struct seccomp_data, arch));
	i++;
	f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		RELIQUARY_AUDIT_ARCH, 0, (__u8)(kill_idx - (i + 1)));
	i++;
	f[i] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		offsetof(struct seccomp_data, nr));
	i++;
# if RELIQUARY_X32
	/*
	 * Reject x32 syscalls (nr | 0x40000000) so they cannot alias a denied
	 * number and slip past the equality checks below.
	 */
	f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
		0x40000000U, (__u8)(kill_idx - (i + 1)), 0);
	i++;
# endif
	for (size_t k = 0; k < ndeny; k++) {
		f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			(unsigned)denylist[k], (__u8)(kill_idx - (i + 1)), 0);
		i++;
	}
	f[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
		SECCOMP_RET_ALLOW);
	i++;
	f[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
		SECCOMP_RET_KILL_PROCESS);
	i++;

	struct sock_fprog prog = {
		.len = (unsigned short)i,
		.filter = f,
	};

	/*
	 * PR_SET_SECCOMP requires either CAP_SYS_ADMIN or no-new-privs; the
	 * daemon is unprivileged, so assert no-new-privs here (idempotent with
	 * main.c) to keep this routine self-contained.
	 */
	int rc = -1;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
	    && prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0)
		rc = 0;

	free(f);
	return rc;
}

#else /* !RELIQUARY_HAVE_SECCOMP */

int
seccomp_install(void)
{
	if (getenv("RELIQUARY_SKIP_SECCOMP")) {
		log_warn("WARNING: seccomp filter bypassed via RELIQUARY_SKIP_SECCOMP "
			 "(dev/test only)");
		return 0;
	}
	return -1;	/* no seccomp support compiled in for this target */
}

#endif
