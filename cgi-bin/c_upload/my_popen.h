#ifndef _MY_POPEN_H
#define _MY_POPEN_H

#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

FILE *my_popen (const char *cmdstring, const char *type);
int my_pclose (FILE *fp);
int execute (const char *cmd_line, int quiet);
int my_system (const char * cmd);

#endif
