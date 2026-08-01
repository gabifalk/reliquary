/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_LOG_H
#define RELIQUARY_LOG_H

void log_init(int verbosity);

int log_get_level(void);

void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_debug2(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
