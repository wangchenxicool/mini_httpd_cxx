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
#include <time.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include "wcx_log.h"


#define OUTCHAR(c)	(buflen > 0? (--buflen, *buf++ = (c)): 0)

/**
 * @brief
 *
 * @param   buf
 * @param   buflen
 * @param   fmt
 * @param   ...
 *
 * @return
 */
int slprintf (char *buf, int buflen, char *fmt, ...) {

    va_list args;
    int n;

#if defined(__STDC__)
    va_start (args, fmt);
#else
    char *buf;
    int buflen;
    char *fmt;
    va_start (args);
    buf = va_arg (args, char *);
    buflen = va_arg (args, int);
    fmt = va_arg (args, char *);
#endif
    n = vslprintf (buf, buflen, fmt, args);

    va_end (args);

    return n;
}

/**
 * @brief
 *
 * @param   buf
 * @param   buflen
 * @param   fmt
 * @param   args
 *
 * @return
 */
int vslprintf (char *buf, int buflen, const char *fmt, va_list args) {

    int c, i, n;
    int width, prec, fillch;
    int base, len, neg, quoted;
    unsigned long val = 0;
    char *str, *buf0;
    const char *f;
    unsigned char *p;
    char num[32];
    time_t t;
    struct tm *timenow;
    //u_int32_t ip;
    uint32_t ip;
    static char hexchars[] = "0123456789abcdef";

    buf0 = buf;
    --buflen;

    while (buflen > 0) {
        for (f = fmt; *f != '%' && *f != 0; ++f)
            ;
        if (f > fmt) {
            len = f - fmt;
            if (len > buflen)
                len = buflen;
            memcpy (buf, fmt, len);
            buf += len;
            buflen -= len;
            fmt = f;
        }

        if (*fmt == 0) {
            break;
        }

        c = *++fmt;
        width = 0;
        prec = -1;
        fillch = ' ';

        if (c == '0') {
            fillch = '0';
            c = *++fmt;
        }

        if (c == '*') {
            width = va_arg (args, int);
            c = *++fmt;
        } else {
            while (isdigit (c)) {
                width = width * 10 + c - '0';
                c = *++fmt;
            }
        }

        if (c == '.') {
            c = *++fmt;
            if (c == '*') {
                prec = va_arg (args, int);
                c = *++fmt;
            } else {
                prec = 0;
                while (isdigit (c)) {
                    prec = prec * 10 + c - '0';
                    c = *++fmt;
                }
            }
        }

        str = 0;
        base = 0;
        neg = 0;
        ++fmt;

        switch (c) {
        case 'l':
            c = *fmt++;
            switch (c) {
            case 'd':
                val = va_arg (args, long);
                if (val < 0) {
                    neg = 1;
                    val = -val;
                }
                base = 10;
                break;
            case 'u':
                val = va_arg (args, unsigned long);
                base = 10;
                break;
            default:
                OUTCHAR ('%');
                OUTCHAR ('l');
                --fmt;		/* so %lz outputs %lz etc. */
                continue;
            }
            break;
        case 'd':
            i = va_arg (args, int);
            if (i < 0) {
                neg = 1;
                val = -i;
            } else
                val = i;
            base = 10;
            break;
        case 'u':
            val = va_arg (args, unsigned int);
            base = 10;
            break;
        case 'o':
            val = va_arg (args, unsigned int);
            base = 8;
            break;
        case 'x':
        case 'X':
            val = va_arg (args, unsigned int);
            base = 16;
            break;
        case 'p':
            val = (unsigned long) va_arg (args, void *);
            base = 16;
            neg = 2;
            break;
        case 's':
            str = va_arg (args, char *);
            break;
        case 'c':
            num[0] = va_arg (args, int);
            num[1] = 0;
            str = num;
            break;
        case 'm':
            str = strerror (errno);
            break;
        case 'I':
            //ip = va_arg (args, u_int32_t);
            ip = va_arg (args, uint32_t);
            ip = ntohl (ip);
            slprintf (num, sizeof (num), (char*) "%d.%d.%d.%d", (ip >> 24) & 0xff,
                      (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
            str = num;
            break;
        case 't':
            time (&t);
            str = (char*) ctime (&t);
            str += 4;		/* chop off the day name */
            str[15] = 0;	/* chop off year and newline */
            break;
        case 'T':
            time (&t);
            timenow = (struct tm*) localtime (&t);
            str = (char*) asctime (timenow);
            str[ strlen ( (char*) asctime (timenow)) - 1 ] = 0;
            break;
        case 'v':		/* "visible" string */
        case 'q':		/* quoted string */
            quoted = c == 'q';
            p = va_arg (args, unsigned char *);
            if (fillch == '0' && prec >= 0)
                n = prec;
            else {
                n = strlen ( (char *) p);
                if (prec >= 0 && n > prec)
                    n = prec;
            }

            while (n > 0 && buflen > 0) {
                c = *p++;
                --n;

                if (!quoted && c >= 0x80) {
                    OUTCHAR ('M');
                    OUTCHAR ('-');
                    c -= 0x80;
                }

                if (quoted && (c == '"' || c == '\\'))
                    OUTCHAR ('\\');

                if (c < 0x20 || (0x7f <= c && c < 0xa0)) {
                    if (quoted) {
                        OUTCHAR ('\\');
                        switch (c) {
                        case '\t':
                            OUTCHAR ('t');
                            break;
                        case '\n':
                            OUTCHAR ('n');
                            break;
                        case '\b':
                            OUTCHAR ('b');
                            break;
                        case '\f':
                            OUTCHAR ('f');
                            break;
                        default:
                            OUTCHAR ('x');
                            OUTCHAR (hexchars[c >> 4]);
                            OUTCHAR (hexchars[c & 0xf]);
                        }
                    } else {
                        if (c == '\t')
                            OUTCHAR (c);
                        else {
                            OUTCHAR ('^');
                            OUTCHAR (c ^ 0x40);
                        }
                    }
                } else
                    OUTCHAR (c);
            }

            continue;
        case 'B':
            p = va_arg (args, unsigned char *);
            for (n = prec; n > 0; --n) {
                c = *p++;
                if (fillch == ' ')
                    OUTCHAR (' ');
                OUTCHAR (hexchars[ (c >> 4) & 0xf]);
                OUTCHAR (hexchars[c & 0xf]);
            }
            continue;
        default:
            *buf++ = '%';
            if (c != '%')
                --fmt;		/* so %z outputs %z etc. */
            --buflen;
            continue;
        }

        if (base != 0) {
            str = num + sizeof (num);
            *--str = 0;

            while (str > num + neg) {
                *--str = hexchars[val % base];
                val = val / base;
                if (--prec <= 0 && val == 0)
                    break;
            }

            switch (neg) {
            case 1:
                *--str = '-';
                break;
            case 2:
                *--str = 'x';
                *--str = '0';
                break;
            }

            len = num + sizeof (num) - 1 - str;
        } else {
            len = strlen (str);
            if (prec >= 0 && len > prec)
                len = prec;
        }

        if (width > 0) {
            if (width > buflen)
                width = buflen;
            if ( (n = width - len) > 0) {
                buflen -= n;

                for (; n > 0; --n)
                    *buf++ = fillch;
            }
        }

        if (len > buflen)
            len = buflen;

        memcpy (buf, str, len);
        buf += len;
        buflen -= len;
    }

    *buf = 0;
    return buf - buf0;
}

/**
 * @brief
 *
 * @param   file
 * @param   fmt
 * @param   ...
 */
void wcx_log (const char *file, const char *fmt, ...) {

    va_list args;
    char buf[1024 * 2];

    //XXX va..
#if defined(__STDC__)
    va_start (args, fmt);
#else
    char *fmt;
    va_start (args);
    fmt = va_arg (args, char *);
#endif
    memset (buf, 0, sizeof (buf));
    vslprintf (buf, sizeof (buf), fmt, args);
    va_end (args);

    //XXX 获取文件大小
    FILE *filePtr = 0;
    struct stat statbuff;
    int ret =::stat (file, &statbuff);

    //XXX 如果文件不存在或者大于MAX_FILE_SIZE 重新创建日志文件
    if (ret < 0 || statbuff.st_size > MAX_FILE_SIZE) {
        filePtr = fopen (file, "w+");
        if (filePtr) {
            fclose (filePtr);
            filePtr = 0;
        }
    }

    //XXX 追加方式打开文件
    filePtr = fopen (file, "a+");
    if (!filePtr) {
        perror ("fopen");
        return;
    }

    //XXX 写文件
    fwrite (buf, 1, strlen (buf), filePtr);

    //XXX 关闭文件
    if (filePtr) {
        fclose (filePtr);
        filePtr = 0;
    }

}

/**
 * @brief
 *
 * @param   log
 * @param   file
 * @param   soft
 * @param   version
 * @param   author
 * @param   logtype
 */
void log_init (struct log_tp *log,
               const char *file, const char *soft, const char* version) {

    strncpy (log->fileName, file, sizeof (log->fileName));

    char current_file_name[256];
    memset (current_file_name, 0, sizeof (current_file_name));
#ifdef USE_TIME_FILE
    time_t cur_time = time (NULL);
    struct tm *timeinfo = localtime (&cur_time);
    char buffer[] = {"yyyy-mm-dd"};
    strftime (buffer, sizeof (buffer), "%F", timeinfo);
    snprintf (current_file_name, sizeof (current_file_name), "%s-%s.log", log->fileName, buffer);
#else
    snprintf (current_file_name, sizeof (current_file_name), "%s.log", log->fileName);
#endif

    //XXX write log
    wcx_log (current_file_name, "%s\n",
             "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    wcx_log (current_file_name, "%s<%T>\n", "$Log File Created On: ");
    wcx_log (current_file_name, "%s<%s>\n", "$Software: ", soft);
    wcx_log (current_file_name, "%s<%s>\n", "$Editor: ", "wangchenxi");
    wcx_log (current_file_name, "%s<%s>\n\n", "$Version: ", version);
}

/**
 * @brief
 *
 * @param   log
 * @param   fmt
 * @param   ...
 */
void write_log (struct log_tp *log,
                int error_code, const char* file_name,
                int line, const char* func, const char *fmt, ...) {

    va_list args;
#if defined(__STDC__)
    va_start (args, fmt);
#else
    char *fmt;
    va_start (args);
    fmt = va_arg (args, char *);
#endif

    //XXX make message
    char buf[1024 * 2];
    memset (buf, 0, sizeof (buf));
    vslprintf (buf, sizeof (buf), fmt, args);
    va_end (args);

    char current_file_name[256];
    memset (current_file_name, 0, sizeof (current_file_name));
#ifdef USE_TIME_FILE
    time_t cur_time = time (NULL);
    struct tm *timeinfo = localtime (&cur_time);
    char buffer[] = {"yyyy-mm-dd"};
    strftime (buffer, sizeof (buffer), "%F", timeinfo);
    snprintf (current_file_name, sizeof (current_file_name), "%s-%s.log", log->fileName, buffer);
#else
    snprintf (current_file_name, sizeof (current_file_name), "%s.log", log->fileName);
#endif

    //XXX write log
    wcx_log (current_file_name, "[%T][%s:%d][%s][%d]: %s\n", file_name, line, func, error_code, buf);
//    printf ("%s\n", buf);
}

struct log_tp run_log;
