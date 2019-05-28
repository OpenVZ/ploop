/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include "ploop.h"

static int _s_log_enable = 1;
static int _s_log_level = 3;
static int _s_log_verbose_level = PLOOP_LOG_NOCONSOLE; // disable stdout/stderr
static FILE *_s_log_file = NULL;
static struct timeval start = { };


/* Thread Local Storage */
static __thread char _g_log_buf[LOG_BUF_SIZE];

static char *get_buffer(void)
{
	return _g_log_buf;
}

#ifdef PLOOP_LOG_FILE
static FILE *_s_ploop_log_file = NULL;
__attribute__((constructor)) void __ploop_init (void)
{

	_s_ploop_log_file = fopen(PLOOP_LOG_FILE, "a");
}

__attribute__((destructor)) void __ploop_deinit (void)
{
	if (_s_ploop_log_file)
		fclose(_s_ploop_log_file);
}
#endif

static inline void get_date(char *buf, int len)
{
	struct tm *p_tm_time;
	time_t ptime;

	ptime = time(NULL);
	p_tm_time = localtime(&ptime);
	strftime(buf, len, "%Y-%m-%dT%T%z", p_tm_time);
}

static void timediff(struct timeval *from, struct timeval *to)
{
	to->tv_sec -= from->tv_sec;
	if (to->tv_usec >= from->tv_usec)
		to->tv_usec -= from->tv_usec;
	else {
		to->tv_sec--;
		to->tv_usec += 1000000 - from->tv_usec;
	}
}

const static char* get_ts(void)
{
	static char buf[16];
	const static char empty[] = "";
	struct timeval t;

	if (_s_log_verbose_level < PLOOP_LOG_TIMESTAMPS)
		return empty;

	gettimeofday(&t, NULL);
	timediff(&start, &t);
	snprintf(buf, sizeof(buf), "[%2u.%06u] ",
			(unsigned)t.tv_sec, (unsigned)t.tv_usec);

	return buf;
}

static void logger_ap(int level, int err_no, const char *format, va_list ap)
{
	char buf[LOG_BUF_SIZE];
	char date[64];
	char *err_buf;
	int r;
	int errno_tmp = errno;
	FILE *std = (level < 0 ? stderr : stdout);

	r = vsnprintf(buf, sizeof(buf), format, ap);
	if ((r < sizeof(buf) - 1) && err_no) {
		snprintf(buf + r, sizeof(buf) - r, ": %s",
			 strerror(err_no));
	}

#ifdef PLOOP_LOG_FILE
	if (_s_ploop_log_file && _s_log_level >= level) {
		get_date(date, sizeof(date));
		fprintf(_s_ploop_log_file, "%s pid=%d: %s\n", date, getpid(), buf);
		fflush(_s_ploop_log_file);
	}
#endif

	if (_s_log_enable) {
		if (_s_log_verbose_level != PLOOP_LOG_NOCONSOLE &&
				_s_log_verbose_level >= level) {
			fprintf(std, "%s%s\n", get_ts(), buf);
			fflush(std);
		}

		if (_s_log_level >= level && _s_log_file != NULL) {
			get_date(date, sizeof(date));
			fprintf(_s_log_file, "%s : %s\n", date, buf);
			fflush(_s_log_file);
		}
	}
	if (level < 0 && (err_buf = get_buffer()) != NULL)
		strcpy(err_buf, buf); /* Preserve error */
	errno = errno_tmp;
}

void ploop_log(int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logger_ap(level, 0, format, ap);
	va_end(ap);
}

void __ploop_err(int err_no, const char *format, ...)
{
	va_list ap;
	int err = errno;

	va_start(ap, format);
	logger_ap(-1, err_no, format, ap);
	va_end(ap);
	errno = err;
}

const char *ploop_get_last_error(void)
{
	return get_buffer();
}

void time_init(void) {
	if (start.tv_sec == 0 && start.tv_usec == 0)
		gettimeofday(&start, NULL);
}

void ploop_set_log_level(int level)
{
	time_init();
	_s_log_level = level;
}

int ploop_get_log_level(void)
{
	return _s_log_level;
}

void ploop_set_verbose_level(int level)
{
	time_init();
	_s_log_verbose_level = level;
}

int ploop_set_log_file(const char *fname)
{
	FILE *fp = NULL;

	time_init();

	if (fname != NULL) {
		fp = fopen(fname, "a");
		if (fp == NULL) {
			__ploop_err(errno, "Can't open %s", fname);
			return -1;
		}
	}

	if (_s_log_file != NULL)
		fclose(_s_log_file);
	_s_log_file = fp;

	return 0;
}
