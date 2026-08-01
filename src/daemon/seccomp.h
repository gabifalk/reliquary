/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_SECCOMP_H
#define RELIQUARY_SECCOMP_H

/*
 * Install a seccomp-BPF syscall denylist on the calling process. The filter is
 * inherited across fork(), so installing it once in the daemon parent covers
 * every connection-handling child.
 *
 * The list denies syscalls that neither the accept loop nor a connection child
 * ever legitimately needs after startup (execve, socket, ptrace, module and
 * namespace manipulation, and known exploitation primitives). A denied syscall
 * kills the offending process; it is not a graceful error. Path-based
 * filtering (e.g. restricting open) is out of scope for classic seccomp-BPF.
 *
 * Returns 0 on success, -1 if no filter could be installed -- an unsupported
 * CPU architecture, or a kernel built without seccomp support. Callers that
 * require the hardening (the daemon) treat -1 as fatal.
 *
 * RELIQUARY_SKIP_SECCOMP (dev/test only): when set in the environment, logs a
 * warning to stderr and returns 0 without installing any filter.
 */
int seccomp_install(void);

#endif
