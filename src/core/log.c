/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE
#include "log.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

static int log_level = 0;

void
log_init(int verbosity)
{
	if (verbosity < 0)
		verbosity = 0;
	if (verbosity > 2)
		verbosity = 2;
	log_level = verbosity;
}

int
log_get_level(void)
{
	return log_level;
}

static void
emit(const char *prefix, const char *fmt, va_list ap)
{
	char buf[1024];
	int n = 0;
	int r = snprintf(buf, sizeof(buf), "%s", prefix);
	if (r > 0)
		n = r < (int)sizeof(buf) ? r : (int)sizeof(buf) - 1;
	r = vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	if (r > 0)
		n += r < (int)(sizeof(buf) - n) ? r : (int)(sizeof(buf) - n) - 1;
	if (n > (int)sizeof(buf) - 1)
		n = (int)sizeof(buf) - 1;	/* leave room for '\n' */
	buf[n++] = '\n';
	(void)!write(STDERR_FILENO, buf, (size_t)n);
}

static void
emit_named(const char *fmt, va_list ap)
{
	char prefix[64];
	snprintf(prefix, sizeof(prefix), "%s[%d]: ",
		 program_invocation_short_name, (int)getpid());
	emit(prefix, fmt, ap);
}

void
log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_named(fmt, ap);
	va_end(ap);
}

void
log_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit_named(fmt, ap);
	va_end(ap);
}

void
log_debug(const char *fmt, ...)
{
	if (log_level < 1)
		return;
	va_list ap;
	va_start(ap, fmt);
	emit("debug1: ", fmt, ap);
	va_end(ap);
}

void
log_debug2(const char *fmt, ...)
{
	if (log_level < 2)
		return;
	va_list ap;
	va_start(ap, fmt);
	emit("debug2: ", fmt, ap);
	va_end(ap);
}
