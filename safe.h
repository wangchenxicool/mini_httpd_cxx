/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

#ifndef _SAFE_H_
#define _SAFE_H_

#include <stdarg.h>             /* For va_list */
#include <sys/types.h>          /* For fork */
#include <unistd.h>             /* For fork */

#define MAX_FD_CLEANUP 16

/** Register an fd for auto-cleanup on fork() */
void register_fd_cleanup_on_fork(const int);

/** @brief Safe version of malloc */
void *safe_malloc(size_t);

/** @brief Safe version of realloc */
void *safe_realloc(void *, size_t);

/* @brief Safe version of strdup */
char *safe_strdup(const char *);

/* @brief Safe version of asprintf */
int safe_asprintf(char **, const char *, ...);

/* @brief Safe version of vasprintf */
int safe_vasprintf(char **, const char *, va_list);

/* @brief Safe version of fork */
pid_t safe_fork(void);

void wcx_sleep (long int s, long int us);

size_t strlcpy (char *dest, const char *src, size_t len);

#endif                          /* _SAFE_H_ */
