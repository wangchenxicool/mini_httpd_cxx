#ifndef _WCX_LOG
#define _WCX_LOG

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <stdarg.h>

#define MAX_FILE_SIZE   (3*1048510) //3M

struct log_tp {
    char fileName[128];
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    int slprintf (char *buf, int buflen, char *fmt, ...);
    int vslprintf (char *buf, int buflen, const char *fmt, va_list args);
    void wcx_log (const char *file, const char *fmt, ...);
    void log_init (struct log_tp *log, const char *file, const char *soft, const char* version);
    void write_log (struct log_tp *log, int error_code, const char* file_name, int line, const char* func, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */
    
#define INIT_LOG(file, soft, version) \
    log_init (&run_log, (file), (soft), (version));

#define DEBUG_LOG(...) \
	do \
	{ \
        write_log (&run_log, 0, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
	} while(0)

#define WARNING_LOG(...) \
	do \
	{ \
        write_log (&run_log, -1, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
	} while(0)

#define ERROR_LOG(...) \
	do \
	{ \
        write_log (&run_log, -2, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
	} while(0)

extern struct log_tp run_log;

#endif
