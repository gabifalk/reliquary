/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_LANDLOCK_H
#define RELIQUARY_LANDLOCK_H

/*
 * Confine the calling process's filesystem access to the subtree rooted at
 * `path` (read, write, create, delete, rename within it) and deny access to
 * every path outside it. The restriction is inherited across fork(), so
 * applying it once in the daemon parent covers every connection child.
 *
 * This is defense in depth on top of the DAC boundary: the owner-gated per-uid
 * store dir already enforces per-user isolation. Landlock additionally stops a
 * compromised daemon from reading or writing anywhere but its own store --
 * closing path-based exfiltration that seccomp cannot.
 *
 * Returns 0 if the confinement was applied (or deliberately skipped via
 * RELIQUARY_SKIP_LANDLOCK), -1 if Landlock is unavailable (kernel < 5.13 or
 * not in the active LSM stack) or the ruleset could not be built. Callers
 * treat -1 as best effort: warn and continue, since DAC still isolates.
 *
 * RELIQUARY_SKIP_LANDLOCK (dev/test only): when set, logs a warning and
 * returns 0 without confining.
 */
int landlock_confine(const char *path);

#endif
