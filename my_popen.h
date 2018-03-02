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
#include <string.h>

int my_system (const char * cmd);

#endif
