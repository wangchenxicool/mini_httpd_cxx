/*================================================================================
  _             ____
 | |__    ____ |  _ \    ___     __ _
 | '_ \  |_  / | | | |  / _ \   / _` |
 | |_) |  / /  | |_| | | (_) | | (_| |
 |_.__/  /___| |____/   \___/   \__, |
                                |___/
================================================================================*/
#ifndef _WCX_BANGBANGDOG_H_
#define _WCX_BANGBANGDOG_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <syslog.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <sys/file.h>
#include <time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/un.h>
#include <vector>

#define WWW_ROOT                    "/njskwww"
#define CGI_DIR                     "/njskwww/cgi-bin"
#define HTTPD_CONF_FILE             "/njskwww/httpd.conf"
#define RUN_STATUS_FILE             "/var/run/run_status_httpd.log"

#define FREE            0
#define BUSY            1
#define CMD_SLEEP                      0
#define CMD_NETWORK_RESTART            1

#define QOS                                     1
#define FLAG_ALLOWED                            88
#define TABLE_BANGBANGDOG_OUTGOING              "BBDog_Outgoing"
#define TABLE_BANGBANGDOG_WIFI_TO_INTERNET      "BBDog_WIFI2Internet"
#define TABLE_BANGBANGDOG_WIFI_TO_ROUTER        "BBDog_WIFI2Router"
#define TABLE_BANGBANGDOG_INCOMING              "BBDog_Incoming"
#define TABLE_BANGBANGDOG_AUTHSERVERS           "BBDog_AuthServers"
#define TABLE_BANGBANGDOG_GLOBAL                "BBDog_Global"
#define TABLE_BANGBANGDOG_VALIDATE              "BBDog_Validate"
#define TABLE_BANGBANGDOG_KNOWN                 "BBDog_Known"
#define TABLE_BANGBANGDOG_UNKNOWN               "BBDog_Unknown"
#define TABLE_BANGBANGDOG_LOCKED                "BBDog_Locked"
#define TABLE_BANGBANGDOG_TRUSTED               "BBDog_Trusted"
#define FW_MARK_PROBATION                       1
#define FW_MARK_KNOWN                           2
#define FW_MARK_LOCKED                          254


#if DEBUG
#define WCX_PRINT(format, arg...)           \
        printf (format , ##arg)
#else
#define WCX_PRINT(format, arg...) {}
#endif

/* port.h - portability defines */
#if defined(__FreeBSD__)
# define OS_FreeBSD
# define ARCH "FreeBSD"
#elif defined(__OpenBSD__)
# define OS_OpenBSD
# define ARCH "OpenBSD"
#elif defined(__NetBSD__)
# define OS_NetBSD
# define ARCH "NetBSD"
#elif defined(linux)
# define OS_Linux
# define ARCH "Linux"
#elif defined(sun)
# define OS_Solaris
# define ARCH "Solaris"
#elif defined(__osf__)
# define OS_DigitalUnix
# define ARCH "DigitalUnix"
#elif defined(__svr4__)
# define OS_SysV
# define ARCH "SysV"
#else
# define OS_UNKNOWN
# define ARCH "UNKNOWN"
#endif

#ifdef OS_FreeBSD
# include <osreldate.h>
# define HAVE_DAEMON
# define HAVE_SETSID
# define HAVE_SETLOGIN
# define HAVE_WAITPID
# define HAVE_HSTRERROR
# define HAVE_TM_GMTOFF
# define HAVE_SENDFILE
# define HAVE_SCANDIR
# define HAVE_INT64T
# ifdef SO_ACCEPTFILTER
#  define HAVE_ACCEPT_FILTERS
#  if ( __FreeBSD_version >= 411000 )
#   define ACCEPT_FILTER_NAME "httpready"
#  else
#   define ACCEPT_FILTER_NAME "dataready"
#  endif
# endif /* SO_ACCEPTFILTER */
#endif /* OS_FreeBSD */

#ifdef OS_OpenBSD
# define HAVE_DAEMON
# define HAVE_SETSID
# define HAVE_SETLOGIN
# define HAVE_WAITPID
# define HAVE_HSTRERROR
# define HAVE_TM_GMTOFF
# define HAVE_SCANDIR
# define HAVE_INT64T
#endif /* OS_OpenBSD */

#ifdef OS_NetBSD
# define HAVE_DAEMON
# define HAVE_SETSID
# define HAVE_SETLOGIN
# define HAVE_WAITPID
# define HAVE_HSTRERROR
# define HAVE_TM_GMTOFF
# define HAVE_SCANDIR
# define HAVE_INT64T
#endif /* OS_NetBSD */

#ifdef OS_Linux
# define HAVE_DAEMON
# define HAVE_SETSID
# define HAVE_WAITPID
# define HAVE_TM_GMTOFF
# define HAVE_SENDFILE
# define HAVE_LINUX_SENDFILE
# define HAVE_SCANDIR
# define HAVE_INT64T
#endif /* OS_Linux */

#ifdef OS_Solaris
# define HAVE_SETSID
# define HAVE_WAITPID
# define HAVE_MEMORY_H
# define HAVE_SIGSET
# define HAVE_INT64T
#endif /* OS_Solaris */

#ifdef OS_DigitalUnix
# define HAVE_SETSID
# define HAVE_SETLOGIN
# define HAVE_WAITPID
# define HAVE_SCANDIR
# define HAVE_TM_GMTOFF
# define NO_SNPRINTF
/* # define HAVE_INT64T */	/* Digital Unix 4.0d doesn't have int64_t */
#endif /* OS_DigitalUnix */

#ifdef OS_SysV
# define HAVE_SETSID
# define HAVE_WAITPID
# define HAVE_MEMORY_H
# define HAVE_SIGSET
#endif /* OS_Solaris */

#define SERVER_SOFTWARE "bangbangdog"
#define SERVER_URL "www.baidu.com"

#ifdef HAVE_SENDFILE
# ifdef HAVE_LINUX_SENDFILE
#  include <sys/sendfile.h>
# else /* HAVE_LINUX_SENDFILE */
#  include <sys/uio.h>
# endif /* HAVE_LINUX_SENDFILE */
#endif /* HAVE_SENDFILE */

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* USE_SSL */

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX 2147483647L
#endif

#ifndef HAVE_INT64T
typedef long long int64_t;
#endif

#ifdef __CYGWIN__
#define timezone  _timezone
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif


#ifndef ERR_DIR
#define ERR_DIR "errors"
#endif /* ERR_DIR */
#ifndef DEFAULT_HTTP_PORT
//#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTP_PORT 2060
#endif /* DEFAULT_HTTP_PORT */
#ifdef USE_SSL
#ifndef DEFAULT_HTTPS_PORT
#define DEFAULT_HTTPS_PORT 443
#endif /* DEFAULT_HTTPS_PORT */
#ifndef DEFAULT_CERTFILE
#define DEFAULT_CERTFILE "mini_httpd.pem"
#endif /* DEFAULT_CERTFILE */
#endif /* USE_SSL */
#ifndef DEFAULT_USER
#define DEFAULT_USER "nobody"
#endif /* DEFAULT_USER */
#ifndef CGI_NICE
#define CGI_NICE 10
#endif /* CGI_NICE */
#ifndef CGI_PATH
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin:/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin"
#endif /* CGI_PATH */
#ifndef CGI_LD_LIBRARY_PATH
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#endif /* CGI_LD_LIBRARY_PATH */
#ifndef AUTH_FILE
#define AUTH_FILE ".htpasswd"
#endif /* AUTH_FILE */
#ifndef READ_TIMEOUT
#define READ_TIMEOUT 60
#endif /* READ_TIMEOUT */
#ifndef WRITE_TIMEOUT
#define WRITE_TIMEOUT 300
#endif /* WRITE_TIMEOUT */
#ifndef DEFAULT_CHARSET
//#define DEFAULT_CHARSET "iso-8859-1"
#define DEFAULT_CHARSET "gbk"
#endif /* DEFAULT_CHARSET */

#define METHOD_UNKNOWN 0
#define METHOD_GET  1
#define METHOD_HEAD 2
#define METHOD_POST 3

/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef USE_IPV6
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
#endif /* USE_IPV6 */
} usockaddr;

struct mime_entry {
    const char* ext;
    size_t ext_len;
    const char* val;
    size_t val_len;
};

struct strlong {
    const char* s;
    long l;
};

typedef int (*F_BBDogRcvCB) (const char * ip, const char * mac, char * rcv_data);
typedef int (*F_BBDogDoCGICB) (int fd, const char * ip, const char *mac, const char * binary, const char ** argp, char * rcv_data);

class c_httpd {
public:
    c_httpd (const char *conf_file);
    ~c_httpd ();

    //static c_httpd *global_self;

    // set debug
    void set_debug () {
        debug = 1;
    }
    // set httpd port
    void set_port (unsigned short httpd_port) {
        port = httpd_port;
    }
    // print about
    ssize_t bb_write (char* buf, size_t size) {
        my_write (buf, size);
    }
    void send_error (int s, const char* title, const char* extra_header, const char* text);
    void httpdOutMsg (int code, const char * details);
    void httpdOutToken (const char *mac, time_t date);
    void httpdOutData (const char *SendData);
    void httpdOutFileHead (long size, char *FileName);
    void httpdOutFileBody (char *SendData, int nsize);
    void httpdOutFileEnd();
    void httpdOutFile (long size, char *FileName, char *SendData);
    // set callback
    void set_rcv_call_back (F_BBDogRcvCB f_cb) {
        f_rcv_cb = f_cb;
    }
    void set_do_cgi_call_back (F_BBDogDoCGICB f_cb) {
        f_do_cgi_cb = f_cb;
    }

    // ÔËÐÐ
    int run ();
    //
    int set_updata_path (const char *path);
    int set_updata_name (const char *name);

private:
    F_BBDogRcvCB f_rcv_cb;
    F_BBDogDoCGICB f_do_cgi_cb;
    char* response;
    size_t response_size, response_len;
    int got_hup;
    int debug;
    unsigned short port;
    char* dir;
    char* data_dir;
    int do_chroot;
    int bbvhost;
    char* user;
    char* cgi_pattern;
    char* url_pattern;
    int no_empty_referers;
    char* local_pattern;
    char* hostname;
    char hostname_buf[500];
    char* logfile;
    char* pidfile;
    char* charset;
    char* p3p;
    int max_age;
    FILE* logfp;
    int listen4_fd, listen6_fd;
#ifdef USE_SSL
    int do_ssl;
    char* certfile;
    char* cipher;
    SSL_CTX* ssl_ctx;
#endif /* USE_SSL */
    char cwd[MAXPATHLEN];

    /* Request variables. */
    int conn_fd;
#ifdef USE_SSL
    SSL* ssl;
#endif /* USE_SSL */
    usockaddr client_addr;
    char* request, *request_bk;
    size_t request_size, request_len, request_idx;
    size_t request_bk_size, request_bk_len, request_bk_idx;
    int method;
    char* path;
    char* file;
    char* pathinfo;
    struct stat sb;
    char* query;
    char* protocol;
    int status;
    off_t bytes;
    char* req_hostname;

    char* authorization;
    size_t content_length;
    char* content_type;
    char* cookie;
    char* host;
    time_t if_modified_since;
    char* referer;
    char* useragent;
    char* remoteuser;
    char** envp;

    char* crypt (const char* key, const char* setting) {}
    void init_fw (void);
    void usage (void);
    void read_config (const char * filename);
    void value_required (char* name, char* value);
    void no_value_required (char* name, char* value);
    int initialize_listen_socket (usockaddr* usaP);
    void handle_request (void);
    void de_dotdot (char* file);
    int get_pathinfo (void);
    void do_file (void);
    void do_dir (void);
#ifdef HAVE_SCANDIR
    char* file_details (const char* dir, const char* name);
    void strencode (char* to, size_t tosize, const char* from);
#endif /* HAVE_SCANDIR */
    void do_cgi (void);
    void cgi_interpose_input (int wfd);
    void post_post_garbage_hack (void);
    void cgi_interpose_output (int rfd, int parse_headers);
    char** make_argp (void);
    char** make_envp (void);
    char* build_env (const char* fmt, const char* arg);
    void auth_check (char* dirname);
    void send_authenticate (char* realm);
    char* virtual_file (char* file);
    void send_error_body (int s, const char* title, const char* text);
    int send_error_file (char* filename);
    void send_error_tail (void);
    void add_headers (int s, const char* title, const char* extra_header, const char* me, const char* mt, off_t b, time_t mod);
    void start_request (void);
    void add_to_request (char* str, size_t len);
    void add_to_request_xh (char* str, size_t len);
    char* get_request_line (void);
    void start_response (void);
    void add_to_response (char* str, size_t len);
    void send_response (void);
    void send_via_write (int fd, off_t size);
    ssize_t my_read (char* buf, size_t size);
    ssize_t my_write (char* buf, size_t size);
#ifdef HAVE_SENDFILE
    int my_sendfile (int fd, int socket, off_t offset, size_t nbytes);
#endif /* HAVE_SENDFILE */
    void add_to_buf (char** bufP, size_t* bufsizeP, size_t* buflenP, char* str, size_t len);
    void make_log_entry (void);
    void check_referer (void);
    int really_check_referer (void);
    char* get_method_str (int m);
    int ext_compare (const void * a, const void * b);
    void init_mime (void);
    const char* figure_mime (char* name, char* me, size_t me_size);
    void handle_write_timeout (int sig);
    void re_open_logfile (void);
    void lookup_hostname (usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P);
    char* ntoa (usockaddr* usaP);
    int sockaddr_check (usockaddr* usaP);
    size_t sockaddr_len (usockaddr* usaP);
    void strdecode (char* to, char* from);
    int hexit (char c);
    int b64_decode (const char* str, unsigned char* space, int size);
    void set_ndelay (int fd);
    void clear_ndelay (int fd);
    void* e_malloc (size_t size);
    void* e_realloc (void* optr, size_t size);
    char* e_strdup (char* ostr);
#ifdef NO_SNPRINTF
    int snprintf (char* str, size_t size, const char* format, ...);
#endif /* NO_SNPRINTF */

    /*
    * strlcpy - like strcpy/strncpy, doesn't overflow destination buffer,
    * always leaves destination null-terminated (for len > 0).
    */
    size_t strlcpy (char *dest, const char *src, size_t len);

    /*
     * strlcat - like strcat/strncat, doesn't overflow destination buffer,
     * always leaves destination null-terminated (for len > 0).
     */
    size_t strlcat (char *dest, const char *src, size_t len);

    void *safe_malloc (size_t size);

    char *safe_strdup (const char *s);

    int safe_asprintf (char **strp, const char *fmt, ...);

    int safe_vasprintf (char **strp, const char *fmt, va_list ap);

    char *arp_get (const char *req_ip);

    int match (const char* pattern, const char* string);

    int match_one (const char* pattern, int patternlen, const char* string);

    void pound_case (char* str);

    int strlong_search (char* str, struct strlong* tab, int n, long* lP);

    int scan_wday (char* str_wday, long* tm_wdayP);

    int scan_mon (char* str_mon, long* tm_monP);

    int is_leap (int year);

    /* Basically the same as mktime(). */
    time_t tm_to_time (struct tm* tmP);

    time_t tdate_parse (char* str);

};

#endif//_WCX_BANGBANGDOG_H_
