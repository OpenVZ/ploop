/*
 *  Copyright (C) 2008-2012, Parallels, Inc. All rights reserved.
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

#define LOG_BUF_SIZE	8192
static int _s_log_enable = 1;
static int _s_log_level = 3;
static int _s_log_verbose_level = -2; // disable stdout/stderr
static FILE *_s_log_file = NULL;
#ifdef __i386__
#include <pthread.h>

/* Workaround for non NPTL glibc
 * Private thread specific data */
static pthread_key_t buf_key;
static pthread_once_t buf_key_once = PTHREAD_ONCE_INIT;

static void buffer_destroy(void *buf)
{
	if (buf != NULL) free(buf);
}

static void buffer_key_alloc(void)
{
	pthread_key_create(&buf_key, buffer_destroy);
	pthread_setspecific(buf_key, calloc(1, LOG_BUF_SIZE));
}

static char *get_buffer(void)
{
	pthread_once(&buf_key_once, buffer_key_alloc);
	return pthread_getspecific(buf_key);
}
#else
/* Thread Local Storage */
static __thread char _g_log_buf[LOG_BUF_SIZE];

static char *get_buffer(void)
{
	return _g_log_buf;
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
	if (_s_log_enable) {
		if (_s_log_verbose_level != -2 && _s_log_verbose_level >= level) {
			fprintf(std, "%s\n", buf);
			fflush(std);
		}

		if (_s_log_level > level && _s_log_file != NULL) {
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

void ploop_err(int err_no, const char *format, ...)
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

void ploop_set_log_level(int level)
{
	_s_log_level = level;
}

void ploop_set_verbose_level(int level)
{
	_s_log_verbose_level = level;
}

int ploop_set_log_file(const char *fname)
{
	FILE *fp;

	fp = fopen(fname, "a");
	if (fp== NULL) {
		ploop_err(errno, "Can't open %s", fname);
		return -1;
	}
	if (_s_log_file != NULL)
		fclose(_s_log_file);
	_s_log_file = fp;
	return 0;
}
