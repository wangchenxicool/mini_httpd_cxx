/*================================================================================
  _       _     _                 _
 | |__   | |_  | |_   _ __     __| |
 | '_ \  | __| | __| | '_ \   / _` |
 | | | | | |_  | |_  | |_) | | (_| |
 |_| |_|  \__|  \__| | .__/   \__,_|
                     |_|
================================================================================*/
#include "httpd.h"
#include "bb_client.h"
#include "wcx_log.h"

/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

int b64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, /* 40-4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 /* F0-FF */
};

static struct mime_entry enc_tab[] = {
//#include "mime_encodings.h"
    { "Z", 0, "compress", 0 },
    { "gz", 0, "gzip", 0 },
    { "uu", 0, "x-uuencode", 0 },
};

static struct mime_entry typ_tab[] = {
//#include "mime_types.h"
    { "a", 0, "application/octet-stream", 0 },
    { "aab", 0, "application/x-authorware-bin", 0 },
    { "aam", 0, "application/x-authorware-map", 0 },
    { "aas", 0, "application/x-authorware-seg", 0 },
    { "ai", 0, "application/postscript", 0 },
    { "aif", 0, "audio/x-aiff", 0 },
    { "aifc", 0, "audio/x-aiff", 0 },
    { "aiff", 0, "audio/x-aiff", 0 },
    { "asc", 0, "text/plain", 0 },
    { "asf", 0, "video/x-ms-asf", 0 },
    { "asx", 0, "video/x-ms-asf", 0 },
    { "au", 0, "audio/basic", 0 },
    { "avi", 0, "video/x-msvideo", 0 },
    { "bcpio", 0, "application/x-bcpio", 0 },
    { "bin", 0, "application/octet-stream", 0 },
    { "bmp", 0, "image/bmp", 0 },
    { "cdf", 0, "application/x-netcdf", 0 },
    { "class", 0, "application/x-java-vm", 0 },
    { "cpio", 0, "application/x-cpio", 0 },
    { "cpt", 0, "application/mac-compactpro", 0 },
    { "crl", 0, "application/x-pkcs7-crl", 0 },
    { "crt", 0, "application/x-x509-ca-cert", 0 },
    { "csh", 0, "application/x-csh", 0 },
    { "css", 0, "text/css", 0 },
    { "dcr", 0, "application/x-director", 0 },
    { "dir", 0, "application/x-director", 0 },
    { "djv", 0, "image/vnd.djvu", 0 },
    { "djvu", 0, "image/vnd.djvu", 0 },
    { "dll", 0, "application/octet-stream", 0 },
    { "dms", 0, "application/octet-stream", 0 },
    { "doc", 0, "application/msword", 0 },
    { "dtd", 0, "text/xml", 0 },
    { "dump", 0, "application/octet-stream", 0 },
    { "dvi", 0, "application/x-dvi", 0 },
    { "dxr", 0, "application/x-director", 0 },
    { "eps", 0, "application/postscript", 0 },
    { "etx", 0, "text/x-setext", 0 },
    { "exe", 0, "application/octet-stream", 0 },
    { "ez", 0, "application/andrew-inset", 0 },
    { "fgd", 0, "application/x-director", 0 },
    { "fh", 0, "image/x-freehand", 0 },
    { "fh4", 0, "image/x-freehand", 0 },
    { "fh5", 0, "image/x-freehand", 0 },
    { "fh7", 0, "image/x-freehand", 0 },
    { "fhc", 0, "image/x-freehand", 0 },
    { "gif", 0, "image/gif", 0 },
    { "gtar", 0, "application/x-gtar", 0 },
    { "hdf", 0, "application/x-hdf", 0 },
    { "hqx", 0, "application/mac-binhex40", 0 },
    { "htm", 0, "text/html; charset=%s", 0 },
    { "html", 0, "text/html; charset=%s", 0 },
    { "ice", 0, "x-conference/x-cooltalk", 0 },
    { "ief", 0, "image/ief", 0 },
    { "iges", 0, "model/iges", 0 },
    { "igs", 0, "model/iges", 0 },
    { "iv", 0, "application/x-inventor", 0 },
    { "jar", 0, "application/x-java-archive", 0 },
    { "jfif", 0, "image/jpeg", 0 },
    { "jpe", 0, "image/jpeg", 0 },
    { "jpeg", 0, "image/jpeg", 0 },
    { "jpg", 0, "image/jpeg", 0 },
    { "js", 0, "application/x-javascript", 0 },
    { "kar", 0, "audio/midi", 0 },
    { "latex", 0, "application/x-latex", 0 },
    { "lha", 0, "application/octet-stream", 0 },
    { "lzh", 0, "application/octet-stream", 0 },
    { "m3u", 0, "audio/x-mpegurl", 0 },
    { "man", 0, "application/x-troff-man", 0 },
    { "mathml", 0, "application/mathml+xml", 0 },
    { "me", 0, "application/x-troff-me", 0 },
    { "mesh", 0, "model/mesh", 0 },
    { "mid", 0, "audio/midi", 0 },
    { "midi", 0, "audio/midi", 0 },
    { "mif", 0, "application/vnd.mif", 0 },
    { "mime", 0, "message/rfc822", 0 },
    { "mml", 0, "application/mathml+xml", 0 },
    { "mov", 0, "video/quicktime", 0 },
    { "movie", 0, "video/x-sgi-movie", 0 },
    { "mp2", 0, "audio/mpeg", 0 },
    { "mp3", 0, "audio/mpeg", 0 },
    { "mp4", 0, "video/mp4", 0 },
    { "mpe", 0, "video/mpeg", 0 },
    { "mpeg", 0, "video/mpeg", 0 },
    { "mpg", 0, "video/mpeg", 0 },
    { "mpga", 0, "audio/mpeg", 0 },
    { "ms", 0, "application/x-troff-ms", 0 },
    { "msh", 0, "model/mesh", 0 },
    { "mv", 0, "video/x-sgi-movie", 0 },
    { "mxu", 0, "video/vnd.mpegurl", 0 },
    { "nc", 0, "application/x-netcdf", 0 },
    { "o", 0, "application/octet-stream", 0 },
    { "oda", 0, "application/oda", 0 },
    { "ogg", 0, "application/x-ogg", 0 },
    { "pac", 0, "application/x-ns-proxy-autoconfig", 0 },
    { "pbm", 0, "image/x-portable-bitmap", 0 },
    { "pdb", 0, "chemical/x-pdb", 0 },
    { "pdf", 0, "application/pdf", 0 },
    { "pgm", 0, "image/x-portable-graymap", 0 },
    { "pgn", 0, "application/x-chess-pgn", 0 },
    { "png", 0, "image/png", 0 },
    { "pnm", 0, "image/x-portable-anymap", 0 },
    { "ppm", 0, "image/x-portable-pixmap", 0 },
    { "ppt", 0, "application/vnd.ms-powerpoint", 0 },
    { "ps", 0, "application/postscript", 0 },
    { "qt", 0, "video/quicktime", 0 },
    { "ra", 0, "audio/x-realaudio", 0 },
    { "ram", 0, "audio/x-pn-realaudio", 0 },
    { "ras", 0, "image/x-cmu-raster", 0 },
    { "rdf", 0, "application/rdf+xml", 0 },
    { "rgb", 0, "image/x-rgb", 0 },
    { "rm", 0, "audio/x-pn-realaudio", 0 },
    { "roff", 0, "application/x-troff", 0 },
    { "rpm", 0, "audio/x-pn-realaudio-plugin", 0 },
    { "rss", 0, "application/rss+xml", 0 },
    { "rtf", 0, "text/rtf", 0 },
    { "rtx", 0, "text/richtext", 0 },
    { "sgm", 0, "text/sgml", 0 },
    { "sgml", 0, "text/sgml", 0 },
    { "sh", 0, "application/x-sh", 0 },
    { "shar", 0, "application/x-shar", 0 },
    { "silo", 0, "model/mesh", 0 },
    { "sit", 0, "application/x-stuffit", 0 },
    { "skd", 0, "application/x-koan", 0 },
    { "skm", 0, "application/x-koan", 0 },
    { "skp", 0, "application/x-koan", 0 },
    { "skt", 0, "application/x-koan", 0 },
    { "smi", 0, "application/smil", 0 },
    { "smil", 0, "application/smil", 0 },
    { "snd", 0, "audio/basic", 0 },
    { "so", 0, "application/octet-stream", 0 },
    { "spl", 0, "application/x-futuresplash", 0 },
    { "src", 0, "application/x-wais-source", 0 },
    { "stc", 0, "application/vnd.sun.xml.calc.template", 0 },
    { "std", 0, "application/vnd.sun.xml.draw.template", 0 },
    { "sti", 0, "application/vnd.sun.xml.impress.template", 0 },
    { "stw", 0, "application/vnd.sun.xml.writer.template", 0 },
    { "sv4cpio", 0, "application/x-sv4cpio", 0 },
    { "sv4crc", 0, "application/x-sv4crc", 0 },
    { "svg", 0, "image/svg+xml", 0 },
    { "svgz", 0, "image/svg+xml", 0 },
    { "swf", 0, "application/x-shockwave-flash", 0 },
    { "sxc", 0, "application/vnd.sun.xml.calc", 0 },
    { "sxd", 0, "application/vnd.sun.xml.draw", 0 },
    { "sxg", 0, "application/vnd.sun.xml.writer.global", 0 },
    { "sxi", 0, "application/vnd.sun.xml.impress", 0 },
    { "sxm", 0, "application/vnd.sun.xml.math", 0 },
    { "sxw", 0, "application/vnd.sun.xml.writer", 0 },
    { "t", 0, "application/x-troff", 0 },
    { "tar", 0, "application/x-tar", 0 },
    { "tcl", 0, "application/x-tcl", 0 },
    { "tex", 0, "application/x-tex", 0 },
    { "texi", 0, "application/x-texinfo", 0 },
    { "texinfo", 0, "application/x-texinfo", 0 },
    { "tif", 0, "image/tiff", 0 },
    { "tiff", 0, "image/tiff", 0 },
    { "tr", 0, "application/x-troff", 0 },
    { "tsp", 0, "application/dsptype", 0 },
    { "tsv", 0, "text/tab-separated-values", 0 },
    { "txt", 0, "text/plain; charset=%s", 0 },
    { "ustar", 0, "application/x-ustar", 0 },
    { "vcd", 0, "application/x-cdlink", 0 },
    { "vrml", 0, "model/vrml", 0 },
    { "vx", 0, "video/x-rad-screenplay", 0 },
    { "wav", 0, "audio/x-wav", 0 },
    { "wax", 0, "audio/x-ms-wax", 0 },
    { "wbmp", 0, "image/vnd.wap.wbmp", 0 },
    { "wbxml", 0, "application/vnd.wap.wbxml", 0 },
    { "wm", 0, "video/x-ms-wm", 0 },
    { "wma", 0, "audio/x-ms-wma", 0 },
    { "wmd", 0, "application/x-ms-wmd", 0 },
    { "wml", 0, "text/vnd.wap.wml", 0 },
    { "wmlc", 0, "application/vnd.wap.wmlc", 0 },
    { "wmls", 0, "text/vnd.wap.wmlscript", 0 },
    { "wmlsc", 0, "application/vnd.wap.wmlscriptc", 0 },
    { "wmv", 0, "video/x-ms-wmv", 0 },
    { "wmx", 0, "video/x-ms-wmx", 0 },
    { "wmz", 0, "application/x-ms-wmz", 0 },
    { "wrl", 0, "model/vrml", 0 },
    { "wsrc", 0, "application/x-wais-source", 0 },
    { "wvx", 0, "video/x-ms-wvx", 0 },
    { "xbm", 0, "image/x-xbitmap", 0 },
    { "xht", 0, "application/xhtml+xml", 0 },
    { "xhtml", 0, "application/xhtml+xml", 0 },
    { "xls", 0, "application/vnd.ms-excel", 0 },
    { "xml", 0, "text/xml", 0 },
    { "xpm", 0, "image/x-xpixmap", 0 },
    { "xsl", 0, "text/xml", 0 },
    { "xwd", 0, "image/x-xwindowdump", 0 },
    { "xyz", 0, "chemical/x-xyz", 0 },
    { "zip", 0, "application/zip", 0 },
};

const int n_enc_tab = sizeof (enc_tab) / sizeof (*enc_tab);
const int n_typ_tab = sizeof (typ_tab) / sizeof (*typ_tab);

#define WCX_DEBUG(fmt, ...)     wcx_debug(__FILE__, __LINE__, fmt, __VA_ARGS__)
static void wcx_debug (const char *file, int line, const char *fmt, ...) {
#if DEBUG
    va_list ap;
    fprintf (stderr, "\033[0;31;40mDEBUG\a\033[0m(%s:%d:%d): ", file, line, getpid());
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
#endif
}

static void g_handle_read_timeout (int sig) {
    syslog (LOG_INFO, "connection timed out reading");
    exit (1);
}

static void g_handle_sigterm (int sig) {
    /* Don't need to set up the handler again, since it's a one-shot. */
    syslog (LOG_NOTICE, "exiting due to signal %d", sig);
    (void) fprintf (stderr, "%s: exiting due to signal %d\n", "BBDog", sig);
    closelog();
    exit (1);
}

/* SIGHUP says to re-open the log file. */
static void g_handle_sighup (int sig) {
    const int oerrno = errno;

#ifndef HAVE_SIGSET
    /* Set up handler again. */
    (void) signal (SIGHUP, g_handle_sighup);
    (void) signal (SIGHUP, SIG_IGN);
#endif /* ! HAVE_SIGSET */

    /* Just set a flag that we got the signal. */
    //got_hup = 1;

    /* Restore previous errno. */
    errno = oerrno;
}

static void g_handle_sigchld (int sig) {
    const int oerrno = errno;
    pid_t pid;
    int status;

#ifndef HAVE_SIGSET
    /* Set up handler again. */
    (void) signal (SIGCHLD, g_handle_sigchld);
#endif /* ! HAVE_SIGSET */

    /* Reap defunct children until there aren't any more. */
    for (;;) {
#ifdef HAVE_WAITPID
        pid = waitpid ( (pid_t) - 1, &status, WNOHANG);
#else /* HAVE_WAITPID */
        pid = wait3 (&status, WNOHANG, (struct rusage*) 0);
#endif /* HAVE_WAITPID */
        if ( (int) pid == 0)		/* none left */
            break;
        if ( (int) pid < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            /* ECHILD shouldn't happen with the WNOHANG option,
            ** but with some kernels it does anyway.  Ignore it.
            */
            if (errno != ECHILD) {
                syslog (LOG_ERR, "child wait - %m");
                perror ("child wait");
            }
            break;
        }
    }

    /* Restore previous errno. */
    errno = oerrno;
}

c_httpd::c_httpd (const char *conf_file) {

    //XXX 内部变量初始化
    f_rcv_cb = NULL;
    f_do_cgi_cb = NULL;
    port = 0;
    debug = 0;
    dir = (char*) 0;
    data_dir = (char*) 0;
    do_chroot = 0;
    bbvhost = 0;
    cgi_pattern = (char*) 0;
    url_pattern = (char*) 0;
    no_empty_referers = 0;
    local_pattern = (char*) 0;
    charset = (char*) DEFAULT_CHARSET;
    p3p = (char*) 0;
    max_age = -1;
    user = (char*) DEFAULT_USER;
    hostname = (char*) 0;
    logfile = (char*) 0;
    pidfile = (char*) 0;
    logfp = (FILE*) 0;
#ifdef USE_SSL
    do_ssl = 0;
    certfile = DEFAULT_CERTFILE;
    cipher = (char*) 0;
#endif /* USE_SSL */

    //XXX 读httpd配置文件
    if (conf_file == NULL) {
        read_config (HTTPD_CONF_FILE);
    } else {
        read_config (conf_file);
    }
    logfile = NULL; //不写日志
}

c_httpd::~c_httpd () {
}

/**
 * @brief    run
 *
 * @return
 */
int c_httpd::run () {

    struct passwd* pwd;
    uid_t uid = 32767;
    gid_t gid = 32767;
    usockaddr host_addr4;
    usockaddr host_addr6;
    int gotv4, gotv6;
    fd_set lfdset;
    int maxfd;
    usockaddr usa;
    int sz, r;
    char* cp;

    if (port == 0) {
#ifdef USE_SSL
        if (do_ssl) {
            port = DEFAULT_HTTPS_PORT;
        } else {
            port = DEFAULT_HTTP_PORT;
        }
#else /* USE_SSL */
        port = DEFAULT_HTTP_PORT;
#endif /* USE_SSL */
    }

    //XXX Log file. 
    if (logfile != (char*) 0) {
        logfp = fopen (logfile, "a");
        if (logfp == (FILE*) 0) {
            syslog (LOG_CRIT, "%s - %m", logfile);
            perror (logfile);
        }
        if (logfile[0] != '/') {
            syslog (LOG_WARNING, "logfile is not an absolute path, you may not be able to re-open it");
            (void) fprintf (stderr, "%s: logfile is not an absolute path, you may not be able to re-open it\n", "BBDog");
        }
        if (getuid() == 0) {
            /* If we are root then we chown the log file to the user we'll
            ** be switching to.
            */
            if (fchown (fileno (logfp), uid, gid) < 0) {
                syslog (LOG_WARNING, "fchown logfile - %m");
                perror ("fchown logfile");
                printf ("logfile:%s\n", logfile);
            }
        }
    }

    //XXX Look up hostname. 
    lookup_hostname (
        &host_addr4, sizeof (host_addr4), &gotv4,
        &host_addr6, sizeof (host_addr6), &gotv6);
    if (hostname == (char*) 0) {
        (void) gethostname (hostname_buf, sizeof (hostname_buf));
        hostname = hostname_buf;
    }
    if (! (gotv4 || gotv6)) {
        syslog (LOG_CRIT, "can't find any valid address");
        (void) fprintf (stderr, "%s: can't find any valid address\n", "BBDog");
        exit (1);
    }

    /* Initialize listen sockets.  Try v6 first because of a Linux peculiarity;
    ** like some other systems, it has magical v6 sockets that also listen for
    ** v4, but in Linux if you bind a v4 socket first then the v6 bind fails.
    */
    //if (gotv6)
    if (0) {
        listen6_fd = initialize_listen_socket (&host_addr6);
    } else {
        listen6_fd = -1;
    }
    if (gotv4) {
        listen4_fd = initialize_listen_socket (&host_addr4);
    } else {
        listen4_fd = -1;
    }
    /* If we didn't get any valid sockets, fail. */
    if (listen4_fd == -1 && listen6_fd == -1) {
        syslog (LOG_CRIT, "can't bind to any address");
        (void) fprintf (stderr, "%s: can't bind to any address\n", "BBDog");
        exit (1);
    }

#ifdef USE_SSL
    if (do_ssl) {
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        ssl_ctx = SSL_CTX_new (SSLv23_server_method());
        if (certfile[0] != '\0') {
            if (SSL_CTX_use_certificate_file (ssl_ctx, certfile, SSL_FILETYPE_PEM) == 0 ||
                    SSL_CTX_use_PrivateKey_file (ssl_ctx, certfile, SSL_FILETYPE_PEM) == 0 ||
                    SSL_CTX_check_private_key (ssl_ctx) == 0) {
                ERR_print_errors_fp (stderr);
                exit (1);
            }
        }
        if (cipher != (char*) 0) {
            if (SSL_CTX_set_cipher_list (ssl_ctx, cipher) == 0) {
                ERR_print_errors_fp (stderr);
                exit (1);
            }
        }
    }
#endif /* USE_SSL */

    //XXX set daemon
#if 0
    if (!debug) {
        /* Make ourselves a daemon. */
#ifdef HAVE_DAEMON
        if (daemon (1, 1) < 0) {
            syslog (LOG_CRIT, "daemon - %m");
            perror ("daemon");
            exit (1);
        }
#else
        switch (fork()) {
        case 0:
            break;
        case -1:
            syslog (LOG_CRIT, "fork - %m");
            perror ("fork");
            exit (1);
        default:
            exit (0);
        }
#ifdef HAVE_SETSID
        (void) setsid();
#endif
#endif
    } else {
        /* Even if we don't daemonize, we still want to disown our parent
        ** process.
        */
#ifdef HAVE_SETSID
        (void) setsid();
#endif /* HAVE_SETSID */
    }
#endif

    if (pidfile != (char*) 0) {
        /* Write the PID file. */
        FILE* pidfp = fopen (pidfile, "w");
        if (pidfp == (FILE*) 0) {
            syslog (LOG_CRIT, "%s - %m", pidfile);
            perror (pidfile);
            exit (1);
        }
        (void) fprintf (pidfp, "%d\n", (int) getpid());
        (void) fclose (pidfp);
    }

    /* Read zone info now, in case we chroot(). */
    tzset();

    /* Switch directories if requested. */
    if (dir != (char*) 0) {
        if (chdir (dir) < 0) {
            syslog (LOG_CRIT, "chdir - %m");
            perror ("chdir");
            exit (1);
        }
    }

    /* Get current directory. */
    (void) getcwd (cwd, sizeof (cwd) - 1);
    if (cwd[strlen (cwd) - 1] != '/') {
        (void) strcat (cwd, "/");
    }

    /* Chroot if requested. */
    if (do_chroot) {
        if (chroot (cwd) < 0) {
            syslog (LOG_CRIT, "chroot - %m");
            perror ("chroot");
            exit (1);
        }
        /* If we're logging and the logfile's pathname begins with the
        ** chroot tree's pathname, then elide the chroot pathname so
        ** that the logfile pathname still works from inside the chroot
        ** tree.
        */
        if (logfile != (char*) 0) {
            if (strncmp (logfile, cwd, strlen (cwd)) == 0) {
                (void) strcpy (logfile, &logfile[strlen (cwd) - 1]);
                /* (We already guaranteed that cwd ends with a slash, so leaving
                ** that slash in logfile makes it an absolute pathname within
                ** the chroot tree.)
                */
            } else {
                syslog (LOG_WARNING, "logfile is not within the chroot tree, you will not be able to re-open it");
                (void) fprintf (stderr, "%s: logfile is not within the chroot tree, you will not be able to re-open it\n", "BBDog");
            }
        }
        (void) strcpy (cwd, "/");
        /* Always chdir to / after a chroot. */
        if (chdir (cwd) < 0) {
            syslog (LOG_CRIT, "chroot chdir - %m");
            perror ("chroot chdir");
            exit (1);
        }
    }

    /* Switch directories again if requested. */
    if (data_dir != (char*) 0) {
        if (chdir (data_dir) < 0) {
            syslog (LOG_CRIT, "data_dir chdir - %m");
            perror ("data_dir chdir");
            exit (1);
        }
    }

    /* Catch various signals. */
#ifdef HAVE_SIGSET
    (void) sigset (SIGTERM, g_handle_sigterm);
    (void) sigset (SIGINT, g_handle_sigterm);
    (void) sigset (SIGUSR1, g_handle_sigterm);
    (void) sigset (SIGHUP, g_handle_sighup);
    (void) sigset (SIGCHLD, g_handle_sigchld);
    (void) sigset (SIGPIPE, SIG_IGN);
#else /* HAVE_SIGSET */
    (void) signal (SIGTERM, g_handle_sigterm);
    (void) signal (SIGINT, g_handle_sigterm);
    (void) signal (SIGUSR1, g_handle_sigterm);
    (void) signal (SIGHUP, g_handle_sighup);
    (void) signal (SIGHUP, SIG_IGN);
    (void) signal (SIGCHLD, g_handle_sigchld);
    (void) signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */

    got_hup = 0;

    init_mime();

    if (hostname == (char*) 0) {
        syslog (
            LOG_NOTICE, "%.80s starting on port %d", SERVER_SOFTWARE,
            (int) port);
    } else {
        syslog (
            LOG_NOTICE, "%.80s starting on %.80s, port %d", SERVER_SOFTWARE,
            hostname, (int) port);
    }

    //XXX Main loop. 
    for (;;) {

        if (got_hup) {  /* Do we need to re-open the log file? */
            re_open_logfile();
            got_hup = 0;
        }

        /* Do a select() on at least one and possibly two listen fds.
        ** If there's only one listen fd then we could skip the select
        ** and just do the (blocking) accept(), saving one system call;
        ** that's what happened up through version 1.18.  However there
        ** is one slight drawback to that method: the blocking accept()
        ** is not interrupted by a signal call.  Since we definitely want
        ** signals to interrupt a waiting server, we use select() even
        ** if there's only one fd.
        */
        FD_ZERO (&lfdset);
        maxfd = -1;
        if (listen4_fd != -1) {
            FD_SET (listen4_fd, &lfdset);
            if (listen4_fd > maxfd) {
                maxfd = listen4_fd;
            }
        }
        if (listen6_fd != -1) {
            FD_SET (listen6_fd, &lfdset);
            if (listen6_fd > maxfd) {
                maxfd = listen6_fd;
            }
        }
        if (select (maxfd + 1, &lfdset, (fd_set*) 0, (fd_set*) 0, (struct timeval*) 0) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;	/* try again */
            }
            syslog (LOG_CRIT, "select - %m");
            perror ("select");
            exit (1);
        }

        /* Accept the new connection. */
        syslog (LOG_DEBUG, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        syslog (LOG_DEBUG, "!!!!!!!!!!!!!!!!!!!! Accept the new connection. !!!!!!!!!!!!!!!!!!!!");
        syslog (LOG_DEBUG, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        sz = sizeof (usa.sa_in);
        if (listen4_fd != -1 && FD_ISSET (listen4_fd, &lfdset)) {
            conn_fd = accept (listen4_fd, (sockaddr*) &usa.sa_in, (socklen_t*) &sz);
            //-->XXX add by wcx 
#if 0
            LOCK_CLIENT_LIST();
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop (AF_INET, &usa.sa_in.sin_addr, client_ip, sizeof (client_ip));
            if (NULL == client_find_by_ip (client_ip)) {
                t_client_bb tmp_client;
                memset ((void*)&tmp_client, 0, sizeof(tmp_client));
                strlcpy (tmp_client.ip, client_ip, sizeof (tmp_client.ip));
                tmp_client.authed = false;
                if (client_append (&tmp_client)) {
                    syslog (LOG_DEBUG, "add client(%s) sucess!", client_ip);
                    DEBUG_LOG ("add client(%s) sucess!", client_ip);
                } else {
                    syslog (LOG_DEBUG, "client pool fulled!");
                    DEBUG_LOG ("client pool fulled!");
                }
            }
            UNLOCK_CLIENT_LIST();
#endif
            //<--XXX add by wcx 
        } else if (listen6_fd != -1 && FD_ISSET (listen6_fd, &lfdset)) {
            conn_fd = accept (listen6_fd, (sockaddr*) &usa.sa_in, (socklen_t*) &sz);
        } else {
            syslog (LOG_CRIT, "select failure");
            (void) fprintf (stderr, "%s: select failure\n", "BBDog");
            exit (1);
        }

        if (conn_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;	/* try again */
            }
#ifdef EPROTO
            if (errno == EPROTO) {
                continue;	/* try again */
            }
#endif /* EPROTO */
            syslog (LOG_CRIT, "accept - %m");
            perror ("accept");
            exit (1);
        }

        /* Fork a sub-process to handle the connection. */
        r = fork();
        if (r < 0) {
            syslog (LOG_CRIT, "fork - %m");
            perror ("fork");
            exit (1);
        }
        if (r == 0) {
            client_addr = usa;
            if (listen4_fd != -1) {
                (void) close (listen4_fd);
            }
            if (listen6_fd != -1) {
                (void) close (listen6_fd);
            }
            syslog (LOG_DEBUG, "handle_request..start");
            handle_request();
            syslog (LOG_DEBUG, "handle_request..end");
            exit (0);
        }
        (void) close (conn_fd);

    } /* End Main loop */

}

void c_httpd::usage (void) {
#ifdef USE_SSL
    (void) fprintf (stderr, "usage:  %s [-C configfile] [-D] [-S] [-E certfile] [-Y cipher] [-p port] [-d dir] [-dd data_dir] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset] [-P P3P] [-M maxage]\n", "BBDog");
#else /* USE_SSL */
    (void) fprintf (stderr, "usage:  %s [-C configfile] [-D] [-p port] [-d dir] [-dd data_dir] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset] [-P P3P] [-M maxage]\n", "BBDog");
#endif /* USE_SSL */
    exit (1);
}

void c_httpd::read_config (const char * filename) {

    FILE* fp;
    char line[10000];
    char* cp;
    char* cp2;
    char* name;
    char* value;

    fp = fopen (filename, "r");
    if (fp == (FILE*) 0) {
        syslog (LOG_CRIT, "%s - %m", filename);
        perror (filename);
        exit (1);
    }

    while (fgets (line, sizeof (line), fp) != (char*) 0) {
        /* Trim comments. */
        if ( (cp = strchr (line, '#')) != (char*) 0) {
            *cp = '\0';
        }

        /* Skip leading whitespace. */
        cp = line;
        cp += strspn (cp, " \t\012\015");

        /* Split line into words. */
        while (*cp != '\0') {
            /* Find next whitespace. */
            cp2 = cp + strcspn (cp, " \t\012\015");
            /* Insert EOS and advance next-word pointer. */
            while (*cp2 == ' ' || *cp2 == '\t' || *cp2 == '\012' || *cp2 == '\015') {
                *cp2++ = '\0';
            }
            /* Split into name and value. */
            name = cp;
            value = strchr (name, '=');
            if (value != (char*) 0) {
                *value++ = '\0';
            }
            /* Interpret. */
            if (strcasecmp (name, "debug") == 0) {
                no_value_required (name, value);
                debug = 1;
            } else if (strcasecmp (name, "port") == 0) {
                value_required (name, value);
                port = (unsigned short) atoi (value);
            } else if (strcasecmp (name, "dir") == 0) {
                value_required (name, value);
                dir = e_strdup (value);
            } else if (strcasecmp (name, "data_dir") == 0) {
                value_required (name, value);
                data_dir = e_strdup (value);
            } else if (strcasecmp (name, "chroot") == 0) {
                no_value_required (name, value);
                do_chroot = 1;
            } else if (strcasecmp (name, "nochroot") == 0) {
                no_value_required (name, value);
                do_chroot = 0;
            } else if (strcasecmp (name, "user") == 0) {
                value_required (name, value);
                user = e_strdup (value);
            } else if (strcasecmp (name, "cgipat") == 0) {
                value_required (name, value);
                cgi_pattern = e_strdup (value);
            } else if (strcasecmp (name, "urlpat") == 0) {
                value_required (name, value);
                url_pattern = e_strdup (value);
            } else if (strcasecmp (name, "noemptyreferers") == 0) {
                value_required (name, value);
                no_empty_referers = 1;
            } else if (strcasecmp (name, "localpat") == 0) {
                value_required (name, value);
                local_pattern = e_strdup (value);
            } else if (strcasecmp (name, "host") == 0) {
                value_required (name, value);
                hostname = e_strdup (value);
            } else if (strcasecmp (name, "logfile") == 0) {
                value_required (name, value);
                logfile = e_strdup (value);
            } else if (strcasecmp (name, "vhost") == 0) {
                no_value_required (name, value);
                bbvhost = 1;
            } else if (strcasecmp (name, "pidfile") == 0) {
                value_required (name, value);
                pidfile = e_strdup (value);
            } else if (strcasecmp (name, "charset") == 0) {
                value_required (name, value);
                charset = e_strdup (value);
            } else if (strcasecmp (name, "p3p") == 0) {
                value_required (name, value);
                p3p = e_strdup (value);
            } else if (strcasecmp (name, "max_age") == 0) {
                value_required (name, value);
                max_age = atoi (value);
            }
#ifdef USE_SSL
            else if (strcasecmp (name, "ssl") == 0) {
                no_value_required (name, value);
                do_ssl = 1;
            } else if (strcasecmp (name, "certfile") == 0) {
                value_required (name, value);
                certfile = e_strdup (value);
            } else if (strcasecmp (name, "cipher") == 0) {
                value_required (name, value);
                cipher = e_strdup (value);
            }
#endif /* USE_SSL */
            else {
                (void) fprintf (
                    stderr, "%s: unknown config option '%s'\n", "BBDog", name);
                exit (1);
            }

            /* Advance to next word. */
            cp = cp2;
            cp += strspn (cp, " \t\012\015");
        }
    }

    (void) fclose (fp);
}

void c_httpd::value_required (char* name, char* value) {

    if (value == (char*) 0) {
        (void) fprintf (
            stderr, "%s: value required for %s option\n", "BBDog", name);
        exit (1);
    }
}

void c_httpd::no_value_required (char* name, char* value) {

    if (value != (char*) 0) {
        (void) fprintf (
            stderr, "%s: no value required for %s option\n",
            "BBDog", name);
        exit (1);
    }
}

int c_httpd::initialize_listen_socket (usockaddr* usaP) {
    int i;
    int listen_fd;

    /* Check sockaddr. */
    if (! sockaddr_check (usaP)) {
        syslog (
            LOG_ERR, "unknown sockaddr family on listen socket - %d",
            usaP->sa.sa_family);
        (void) fprintf (
            stderr, "%s: unknown sockaddr family on listen socket - %d\n",
            "BBDog", usaP->sa.sa_family);
        return -1;
    }

    listen_fd = socket (usaP->sa.sa_family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        syslog (LOG_CRIT, "socket %.80s - %m", ntoa (usaP));
        perror ("socket");
        return -1;
    }

    (void) fcntl (listen_fd, F_SETFD, 1);

    i = 1;
    if (setsockopt (listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &i, sizeof (i)) < 0) {
        syslog (LOG_CRIT, "setsockopt SO_REUSEADDR - %m");
        perror ("setsockopt SO_REUSEADDR");
        return -1;
    }

    if (bind (listen_fd, &usaP->sa, sockaddr_len (usaP)) < 0) {
        syslog (LOG_CRIT, "bind %.80s - %m", ntoa (usaP));
        perror ("bind");
        return -1;
    }

    if (listen (listen_fd, 1024) < 0) {
        syslog (LOG_CRIT, "listen - %m");
        perror ("listen");
        return -1;
    }

#ifdef HAVE_ACCEPT_FILTERS
    {
        struct accept_filter_arg af;
        (void) bzero (&af, sizeof (af));
        (void) strcpy (af.af_name, ACCEPT_FILTER_NAME);
        (void) setsockopt (listen_fd, SOL_SOCKET, SO_ACCEPTFILTER, (char*) &af, sizeof (af));
    }
#endif /* HAVE_ACCEPT_FILTERS */

    return listen_fd;
}

void c_httpd::httpdOutMsg (int code, const char * details) {
    char *buf;

    safe_asprintf (&buf, "\
HTTP/1.0 200 OK\r\n\
Connection: close\r\n\
Content-type: application/json\r\n\
\r\n\
{\"code\":\"%d\",\"data\":{%s},\"details\":\"OK\"}\n\n",
                   code,
                   details);

    (void) my_write (buf, strlen (buf));

    free (buf);
}

void c_httpd::httpdOutToken (const char *mac, time_t date) {
    char *buf;

    printf ("httpdOutToken::mac:%s,time:%ld\n", mac, date);

#if 1
    safe_asprintf (&buf, "\
HTTP/1.0 200 OK\r\n\
Connection: close\r\n\
Content-type: application/json\r\n\
\r\n\
{\"code\":\"0\",\"data\":{\"mac\":\"%s\",\"time\":\"%d\"},\"details\":\"OK\"}\n\n",
                   mac,
                   date);
#else
    safe_asprintf (&buf, "\
HTTP/1.0 200 OK\r\n\
Access-Control-Allow-Origin: *\r\n\
Server: mini_httpd\r\n\
Transfer-Encoding: chunked\r\n\
Content-Type: application/json\r\n\
\r\n\
{\"code\":\"0\",\"data\":{\"mac\":\"%s\",\"time\":\"%d\"},\"details\":\"OK\"}\n\n",
                   mac,
                   date);
#endif

    (void) my_write (buf, strlen (buf));

    free (buf);
}

void c_httpd::httpdOutData (const char *SendData) {
    char *buf;

    safe_asprintf (&buf, "\
HTTP/1.0 200 OK\r\n\
Connection: close\r\n\
Content-type: application/json\r\n\
\r\n\
%s\n\n", SendData);

    (void) my_write (buf, strlen (buf));

    free (buf);
}

void c_httpd::httpdOutFileHead (long size, char *FileName) {
    char *buf;

    safe_asprintf (&buf, "\
HTTP/1.0 200 OK\r\n\
Content-Disposition:attachment;filename=%s\r\n\
Content-Length:%ld\r\n\
Content-Type:application/octet-stream\r\n\
\r\n", FileName, size);

    (void) my_write (buf, strlen (buf));

    free (buf);
}

void c_httpd::httpdOutFileBody (char *SendData, int nsize) {
    (void) my_write (SendData, nsize);
}

void c_httpd::httpdOutFileEnd() {
    (void) my_write ( (char*) "\n\n", 2);
}

/* This runs in a child process, and exits when done, so cleanup is
** not needed.
*/
void c_httpd::handle_request (void) {
    char* method_str;
    char* line;
    char* cp;
    int r, file_len, i;
    const char* index_names[] = {
        "index.html", "index.htm", "index.xhtml", "index.xht", "Default.htm",
        "index.cgi"
    };

    /* Set up the timeout for reading. */
#ifdef HAVE_SIGSET
    (void) sigset (SIGALRM, g_handle_read_timeout);
#else /* HAVE_SIGSET */
    //(void) signal (SIGALRM, g_handle_read_timeout);
    (void) signal (SIGALRM, g_handle_read_timeout);
#endif /* HAVE_SIGSET */
    (void) alarm (READ_TIMEOUT);

    /* Initialize the request variables. */
    remoteuser = (char*) 0;
    method = METHOD_UNKNOWN;
    path = (char*) 0;
    file = (char*) 0;
    pathinfo = (char*) 0;
    query = (char*) "";
    protocol = (char*) 0;
    status = 0;
    bytes = -1;
    req_hostname = (char*) 0;

    authorization = (char*) 0;
    content_type = (char*) 0;
    content_length = -1;
    cookie = (char*) 0;
    host = (char*) 0;
    if_modified_since = (time_t) - 1;
    referer = (char*) "";
    useragent = (char*) "";


#ifdef TCP_NOPUSH
    /* Set the TCP_NOPUSH socket option, to try and avoid the 0.2 second
    ** delay between sending the headers and sending the data.  A better
    ** solution is writev() (as used in thttpd), or send the headers with
    ** send(MSG_MORE) (only available in Linux so far).
    */
    r = 1;
    (void) setsockopt (
        conn_fd, IPPROTO_TCP, TCP_NOPUSH, (void*) &r, sizeof (r));
#endif /* TCP_NOPUSH */

#ifdef USE_SSL
    if (do_ssl) {
        ssl = SSL_new (ssl_ctx);
        SSL_set_fd (ssl, conn_fd);
        if (SSL_accept (ssl) == 0) {
            ERR_print_errors_fp (stderr);
            exit (1);
        }
    }
#endif /* USE_SSL */

    /* Read in the request. */
    start_request();
    for (;;) {
        char buf[10000];
        int r = my_read (buf, sizeof (buf));
        if (r < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (r <= 0)
            break;
        (void) alarm (READ_TIMEOUT);
        add_to_request (buf, r);
        if (strstr (request, "\015\012\015\012") != (char*) 0 ||
                strstr (request, "\012\012") != (char*) 0)
            break;
    }
    //XXX bk for xu_hui
    //if (request) {
    //add_to_request_xh (request, request_len);
    //for (;;) {
    //char buf[10000];
    //r = my_read (buf, sizeof (buf));
    //if (r < 0 && (errno == EINTR || errno == EAGAIN))
    //continue;
    //if (r <= 0)
    //break;
    //(void) alarm (READ_TIMEOUT);
    //add_to_request_xh (buf, r);
    //}
    //char *p = strstr (request_bk, "\r\n\r\n");
    //if (p) {
    //p += strspn (p, " \t\012\015");
    //request_bk = p;
    //}
    //}
    //XXX bk for xu_hui
    syslog (LOG_DEBUG, "request:{%s}", request);

    if (f_rcv_cb) {
        char * ipaddr = NULL;
        char * client_mac = NULL;
        ipaddr = inet_ntoa (client_addr.sa_in.sin_addr);
        if (ipaddr) {
            client_mac = arp_get ( (const char *) ipaddr);
        } else {
            syslog (LOG_DEBUG, "[%d]:ipaddr is not get.", __LINE__);
        }
        if (client_mac) {
            if (f_rcv_cb (ipaddr, client_mac, request))
                goto got_one;
        } else {
            syslog (LOG_DEBUG, "[%d]:client_mac is not get.", __LINE__);
        }
    }

    /* Parse the first line of the request. */
    method_str = get_request_line();
    //syslog (LOG_DEBUG, "method: %s", method_str);
    if (method_str == (char*) 0) {
        //send_error (400, "Bad Request", "", "Can't parse request.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:Bad Request, Can't parse request.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::method_str == null\n");
        do_file();
        goto got_one;
    }
    path = strpbrk (method_str, " \t\012\015");
    if (path == (char*) 0) {
        //send_error (400, "Bad Request", "", "Can't parse request.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:Bad Request, Can't parse request.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::path == null\n");
        do_file();
        goto got_one;
    }
    *path++ = '\0';
    path += strspn (path, " \t\012\015");
    protocol = strpbrk (path, " \t\012\015");
    if (protocol == (char*) 0) {
        //send_error (400, "Bad Request", "", "Can't parse request.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:Bad Request, Can't parse request.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::protocol == null\n");
        do_file();
        goto got_one;
    }
    *protocol++ = '\0';
    protocol += strspn (protocol, " \t\012\015");
    query = strchr (path, '?');
    if (query == (char*) 0) {
        query = (char*) "";
    } else {
        *query++ = '\0';
    }
    //syslog (LOG_DEBUG, "path: %s", path);

    /* Parse the rest of the request headers. */
    while ( (line = get_request_line()) != (char*) 0) {
        if (line[0] == '\0')
            break;
        else if (strncasecmp (line, "Authorization:", 14) == 0) {
            cp = &line[14];
            cp += strspn (cp, " \t");
            authorization = cp;
        } else if (strncasecmp (line, "Content-Length:", 15) == 0) {
            cp = &line[15];
            cp += strspn (cp, " \t");
            content_length = atol (cp);
        } else if (strncasecmp (line, "Content-Type:", 13) == 0) {
            cp = &line[13];
            cp += strspn (cp, " \t");
            content_type = cp;
        } else if (strncasecmp (line, "Cookie:", 7) == 0) {
            cp = &line[7];
            cp += strspn (cp, " \t");
            cookie = cp;
        } else if (strncasecmp (line, "Host:", 5) == 0) {
            cp = &line[5];
            cp += strspn (cp, " \t");
            host = cp;
            if (strchr (host, '/') != (char*) 0 || host[0] == '.') {
                //send_error (400, "Bad Request", "", "Can't parse request.");
                /* if err
                 * return the index.html
                 * */
                syslog (LOG_DEBUG, "[%d]:Bad Request, Can't parse request.", __LINE__);
                file = (char*) "./index.html";
                stat (file, &sb);
                printf ("do_file::Bad Request, Can't parse request!\n");
                do_file();
                goto got_one;
            }
        } else if (strncasecmp (line, "If-Modified-Since:", 18) == 0) {
            cp = &line[18];
            cp += strspn (cp, " \t");
            if_modified_since = tdate_parse (cp);
        } else if (strncasecmp (line, "Referer:", 8) == 0) {
            cp = &line[8];
            cp += strspn (cp, " \t");
            referer = cp;
        } else if (strncasecmp (line, "User-Agent:", 11) == 0) {
            cp = &line[11];
            cp += strspn (cp, " \t");
            useragent = cp;
        }
    }

    if (strcasecmp (method_str, get_method_str (METHOD_GET)) == 0)
        method = METHOD_GET;
    else if (strcasecmp (method_str, get_method_str (METHOD_HEAD)) == 0)
        method = METHOD_HEAD;
    else if (strcasecmp (method_str, get_method_str (METHOD_POST)) == 0)
        method = METHOD_POST;
    else {
        //send_error (501, "Not Implemented", "", "That method is not implemented.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:That method is not implemented.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::Not Implemented!\n");
        do_file();
        goto got_one;
    }

    strdecode (path, path);
    if (path[0] != '/') {
        //send_error (400, "Bad Request", "", "Bad filename.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:Bad Request, Bad filename.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::Bad Request, Bad filename!\n");
        do_file();
        goto got_one;
    }
    file = & (path[1]);
    de_dotdot (file);
    if (file[0] == '\0') {
        file = (char*) "./";
    }
    if (file[0] == '/' ||
            (file[0] == '.' && file[1] == '.' && (file[2] == '\0' || file[2] == '/'))) {
        //send_error (400, "Bad Request", "", "Illegal filename.");
        /* if err
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:Bad Request, Illegal filename.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::Bad Request, Illegal filename!\n");
        do_file();
        goto got_one;
    }
    if (bbvhost) {
        file = virtual_file (file);
    }
    //syslog (LOG_DEBUG, "file: %s", file);

    /* Set up the timeout for writing. */
#ifdef HAVE_SIGSET
    (void) sigset (SIGALRM, handle_write_timeout);
#else /* HAVE_SIGSET */
    //(void) signal (SIGALRM, handle_write_timeout);
#endif /* HAVE_SIGSET */
    (void) alarm (WRITE_TIMEOUT);

    r = stat (file, &sb);
    if (r < 0) {
        r = get_pathinfo();
    }
    if (r < 0) {
        //send_error (404, "Not Found", "", "File not found.");

        /* if not find file
         * return the index.html
         * */
        syslog (LOG_DEBUG, "[%d]:File not found.", __LINE__);
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::File not found!\n");
        do_file();
        goto got_one;
    }
    file_len = strlen (file);
    if (!S_ISDIR (sb.st_mode)) {
        /* Not a directory. */
        while (file[file_len - 1] == '/') {
            file[file_len - 1] = '\0';
            --file_len;
        }
        printf ("do_file::!S_ISDIR!\n");
        do_file();
    } else {
        char idx[10000];

        /* The filename is a directory.  Is it missing the trailing slash? */
        if (file[file_len - 1] != '/' && pathinfo == (char*) 0) {
            char location[10000];
            if (query[0] != '\0')
                (void) snprintf (location, sizeof (location), "Location: %s/?%s", path, query);
            else
                (void) snprintf (location, sizeof (location), "Location: %s/", path);
            //send_error (302, "Found", location, "Directories must end with a slash.");
            /* if err
             * return the index.html
             * */
            file = (char*) "./index.html";
            stat (file, &sb);
            printf ("do_file::Directories must end with a slash\n");
            do_file();
            goto got_one;
        }

        /* Check for an index file. */
        for (i = 0; i < sizeof (index_names) / sizeof (char*); ++i) {
            (void) snprintf (idx, sizeof (idx), "%s%s", file, index_names[i]);
            if (stat (idx, &sb) >= 0) {
                file = idx;
                printf ("do_file::Check for an index file\n");
                do_file();
                goto got_one;
            }
        }

        /* Nope, no index file, so it's an actual directory request. */
        //do_dir();
        /* if no index file
         * return the index.html
         * */
        file = (char*) "./index.html";
        stat (file, &sb);
        printf ("do_file::no index file, do dir\n");
        do_file();

got_one:
        ;
    }

#ifdef USE_SSL
    SSL_free (ssl);
#endif /* USE_SSL */
}

void c_httpd::de_dotdot (char* file) {
    char* cp;
    char* cp2;
    int l;

    /* Collapse any multiple / sequences. */
    while ( (cp = strstr (file, "//")) != (char*) 0) {
        for (cp2 = cp + 2; *cp2 == '/'; ++cp2)
            continue;
        (void) strcpy (cp + 1, cp2);
    }

    /* Remove leading ./ and any /./ sequences. */
    while (strncmp (file, "./", 2) == 0)
        (void) strcpy (file, file + 2);
    while ( (cp = strstr (file, "/./")) != (char*) 0)
        (void) strcpy (cp, cp + 2);

    /* Alternate between removing leading ../ and removing xxx/../ */
    for (;;) {
        while (strncmp (file, "../", 3) == 0)
            (void) strcpy (file, file + 3);
        cp = strstr (file, "/../");
        if (cp == (char*) 0)
            break;
        for (cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2)
            continue;
        (void) strcpy (cp2 + 1, cp + 4);
    }

    /* Also elide any xxx/.. at the end. */
    while ( (l = strlen (file)) > 3 &&
            strcmp ( (cp = file + l - 3), "/..") == 0) {
        for (cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2)
            continue;
        if (cp2 < file)
            break;
        *cp2 = '\0';
    }
}

int c_httpd::get_pathinfo (void) {
    int r;
    pathinfo = &file[strlen (file)];
    for (;;) {
        do {
            --pathinfo;
            if (pathinfo <= file) {
                pathinfo = (char*) 0;
                return -1;
            }
        } while (*pathinfo != '/');
        *pathinfo = '\0';
        r = stat (file, &sb);
        if (r >= 0) {
            ++pathinfo;
            return r;
        } else
            *pathinfo = '/';
    }
}

/* do_file 来处理页面请求或执行CGI程序。
* 如果是文件则打开文件，读入到buffer中，写到对方conn_fd 。
* 如果是CGI 程序，则执行CGI 的程序。
*/
void c_httpd::do_file (void) {

    char buf[10000];
    char mime_encodings[500];
    const char* mime_type;
    char fixed_mime_type[500];
    char* cp;
    int fd;

    //printf ("\ndo_file: %s\n", file);

    /* Check authorization for this directory. */
    (void) strncpy (buf, file, sizeof (buf));
    cp = strrchr (buf, '/');
    if (cp == (char*) 0)
        (void) strcpy (buf, ".");
    else
        *cp = '\0';
    auth_check (buf);

    /* Check if the filename is the AUTH_FILE itself - that's verboten. */
    if (strcmp (file, AUTH_FILE) == 0 ||
            (strcmp (& (file[strlen (file) - sizeof (AUTH_FILE) + 1]), AUTH_FILE) == 0 &&
             file[strlen (file) - sizeof (AUTH_FILE)] == '/')) {
        syslog (
            LOG_NOTICE, "%.80s URL \"%.80s\" tried to retrieve an auth file",
            ntoa (&client_addr), path);
        send_error (403, "Forbidden", "", "File is protected.");
    }

    /* Referer check. */
    check_referer();

    /* Is it CGI? */
    if (cgi_pattern != (char*) 0 && match (cgi_pattern, file)) {
        do_cgi ();
        if (fd) {
            (void) close (fd);
            fd = 0;
        }
        return;
    } else if (pathinfo != (char*) 0) {
        send_error (404, "!!! Not Found !!!", "", "File not found.");
    }

    fd = open (file, O_RDONLY);
    if (fd < 0) {
        syslog (
            LOG_INFO, "%.80s File \"%.80s\" is protected",
            ntoa (&client_addr), path);
        send_error (403, "Forbidden", "", "File is protected.");
    }
    mime_type = figure_mime (file, mime_encodings, sizeof (mime_encodings));
    (void) snprintf (
        fixed_mime_type, sizeof (fixed_mime_type), mime_type, charset);
    if (if_modified_since != (time_t) - 1 &&
            if_modified_since >= sb.st_mtime) {
        add_headers (
            304, "Not Modified", "", mime_encodings, fixed_mime_type,
            (off_t) - 1, sb.st_mtime);
        send_response();
        return;
    }
    add_headers (
        200, "Ok", "", mime_encodings, fixed_mime_type, sb.st_size,
        sb.st_mtime);
    send_response();
    if (method == METHOD_HEAD) {
        return;
    }

    if (sb.st_size > 0) {	/* ignore zero-length files */
#ifdef HAVE_SENDFILE

#ifndef USE_SSL
        (void) my_sendfile (fd, conn_fd, 0, sb.st_size);
#else /* USE_SSL */
        if (do_ssl) {
            send_via_write (fd, sb.st_size);
        } else {
            (void) my_sendfile (fd, conn_fd, 0, sb.st_size);
        }
#endif /* USE_SSL */

#else /* HAVE_SENDFILE */

        send_via_write (fd, sb.st_size);

#endif /* HAVE_SENDFILE */
    }

    (void) close (fd);
}

//wcx 取消该定义
#ifdef HAVE_SCANDIR
#undef HAVE_SCANDIR
#endif
//

void c_httpd::do_dir (void) {

    char buf[10000];
    size_t buflen;
    char* contents;
    size_t contents_size, contents_len;

#ifdef HAVE_SCANDIR
    int n, i;
    struct dirent **dl;
    char* name_info;
#else /* HAVE_SCANDIR */
    char command[10000];
    FILE* fp;
#endif /* HAVE_SCANDIR */

    syslog (LOG_DEBUG, "do_dir: %s", file);

    if (pathinfo != (char*) 0)
        send_error (404, "Not Found", "", "File not found.");

    /* Check authorization for this directory. */
    auth_check (file);

    /* Referer check. */
    check_referer();



#ifdef HAVE_SCANDIR
    /*
    看wcx是否启用了编译选项HAVE_SCANDIR
    n = scandir (file, &dl, NULL, alphasort);
    if (n < 0)
    {
        syslog (
            LOG_INFO, "%.80s Directory \"%.80s\" is protected",
            ntoa (&client_addr), path);
        send_error (403, "Forbidden", "", "Directory is protected.");
    }
    */

#endif /* HAVE_SCANDIR */

    contents_size = 0;
    buflen = snprintf (buf, sizeof (buf), "\
<HTML>\n\
<HEAD><TITLE>Index of %s</TITLE></HEAD>\n\
<BODY BGCOLOR=\"#99cc99\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
<H4>Index of %s</H4>\n\
<PRE>\n",
                       file, file);
    add_to_buf (&contents, &contents_size, &contents_len, buf, buflen);

#ifdef HAVE_SCANDIR

    for (i = 0; i < n; ++i) {
        name_info = file_details (file, dl[i]->d_name);
        add_to_buf (
            &contents, &contents_size, &contents_len, name_info,
            strlen (name_info));
    }

#else /* HAVE_SCANDIR */
    /* Magic HTML ls command! */
    if (strchr (file, '\'') == (char*) 0) {
        (void) snprintf (
            command, sizeof (command),
            "ls -lgF '%s' | tail +2 | sed -e 's/^\\([^ ][^ ]*\\)\\(  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)\\(  *[^ ][^ ]*\\)  *\\([^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)  *\\(.*\\)$/\\1 \\3  \\4  |\\5/' -e '/ -> /!s,|\\([^*]*\\)$,|<A HREF=\"\\1\">\\1</A>,' -e '/ -> /!s,|\\(.*\\)\\([*]\\)$,|<A HREF=\"\\1\">\\1</A>\\2,' -e '/ -> /s,|\\([^@]*\\)\\(@* -> \\),|<A HREF=\"\\1\">\\1</A>\\2,' -e 's/|//'",
            file);
        fp = popen (command, "r");
        for (;;) {
            size_t r;
            r = fread (buf, 1, sizeof (buf), fp);
            if (r == 0)
                break;
            add_to_buf (&contents, &contents_size, &contents_len, buf, r);
        }
        (void) pclose (fp);
    }
#endif /* HAVE_SCANDIR */

    buflen = snprintf (buf, sizeof (buf), "\
</PRE>\n\
<HR>\n\
<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n\
</BODY>\n\
</HTML>\n",
                       SERVER_URL, SERVER_SOFTWARE);
    add_to_buf (&contents, &contents_size, &contents_len, buf, buflen);

    add_headers (200, "Ok", "", "", "text/html; charset=%s", contents_len, sb.st_mtime);
    if (method != METHOD_HEAD)
        add_to_response (contents, contents_len);
    syslog (LOG_DEBUG, "do_dir send_response: \n%s\n", response);
    send_response();
}


#ifdef HAVE_SCANDIR

char * c_httpd::file_details (const char* dir, const char* name) {
    struct stat sb;
    char f_time[20];
    char encname[1000];
    static char buf[2000];


    (void) snprintf (buf, sizeof (buf), "%s/%s", dir, name);
    if (lstat (buf, &sb) < 0) {
        return (char*) "???";
    }

    (void) strftime (f_time, sizeof (f_time), "%d%b%Y %H:%M", localtime (&sb.st_mtime));


    strencode (encname, sizeof (encname), name);
    (void) snprintf (
        buf, sizeof (buf), "<A HREF=\"%s\">%-32.32s</A>    %15s %14lld\n",
        encname, name, f_time, (int64_t) sb.st_size);
    return buf;
}

/* Copies and encodes a string. */
void c_httpd::strencode (char* to, size_t tosize, const char* from) {
    int tolen;

    for (tolen = 0; *from != '\0' && tolen + 4 < tosize; ++from) {
        if (isalnum (*from) || strchr ("/_.-~", *from) != (char*) 0) {
            *to = *from;
            ++to;
            ++tolen;
        } else {
            (void) sprintf (to, "%%%02x", (int) *from & 0xff);
            to += 3;
            tolen += 3;
        }
    }
    *to = '\0';
}

#endif /* HAVE_SCANDIR */

/**
 * @brief
 */
void c_httpd::do_cgi (void) {

    char** argp;
    int parse_headers;
    char* binary;
    char* directory;

    if (method != METHOD_GET && method != METHOD_POST) {
        send_error (501, "Not Implemented", "", "That method is not implemented for CGI.");
    }

    /* If the socket happens to be using one of the stdin/stdout/stderr
    ** descriptors, move it to another descriptor so that the dup2 calls
    ** below don't screw things up.  We arbitrarily pick fd 3 - if there
    ** was already something on it, we clobber it, but that doesn't matter
    ** since at this point the only fd of interest is the connection.
    ** All others will be closed on exec.
    */
    if (conn_fd == STDIN_FILENO || conn_fd == STDOUT_FILENO || conn_fd == STDERR_FILENO) {
        int newfd = dup2 (conn_fd, STDERR_FILENO + 1);
        if (newfd >= 0)
            conn_fd = newfd;
        /* If the dup2 fails, shrug.  We'll just take our chances.
        ** Shouldn't happen though.
        */
    }

    /* Make the environment vector. */
    envp = make_envp();

    /* Make the argument vector. */
    argp = make_argp();

    /* do bangbangdog */
    directory = e_strdup (file);
    binary = strrchr (directory, '/');
    if (binary == (char*) 0) {
        binary = file;
    } else {
        *binary++ = '\0';
    }

    if (f_do_cgi_cb) {
        char * ipaddr = NULL;
        char * client_mac = NULL;
        ipaddr = inet_ntoa (client_addr.sa_in.sin_addr);
        if (ipaddr) {
            client_mac = arp_get ( (const char *) ipaddr);
        }
        if (f_do_cgi_cb (conn_fd,
                         ipaddr, client_mac,
                         (const char*) binary,
                         (const char**) argp,
                         request_bk))
            return;
    }

    /* Set up stdin.  For POSTs we may have to set up a pipe from an
    ** interposer process, depending on if we've read some of the data
    ** into our buffer.  We also have to do this for all SSL CGIs.
    */
#ifdef USE_SSL
    if ( (method == METHOD_POST && request_len > request_idx) || do_ssl)
#else /* USE_SSL */
    if ( (method == METHOD_POST && request_len > request_idx))
#endif /* USE_SSL */
    {
        int p[2];
        int r;

        if (pipe (p) < 0) {
            send_error (500, "Internal Error", "", "Something unexpected went wrong making a pipe.");
        }
        r = fork();
        if (r < 0) {
            send_error (500, "Internal Error", "", "Something unexpected went wrong forking an interposer.");
        }
        if (r == 0) {
            /* Interposer process. */
            (void) close (p[0]);
            cgi_interpose_input (p[1]);
            exit (0);
        }
        (void) close (p[1]);
        if (p[0] != STDIN_FILENO) {
            (void) dup2 (p[0], STDIN_FILENO);
            (void) close (p[0]);
        }
    } else {
        /* Otherwise, the request socket is stdin. */
        if (conn_fd != STDIN_FILENO) {
            (void) dup2 (conn_fd, STDIN_FILENO);
        }
    }

    /* Set up stdout/stderr.  For SSL, or if we're doing CGI header parsing,
    ** we need an output interposer too.
    */
    if (strncmp (argp[0], "nph-", 4) == 0) {
        parse_headers = 0;
    } else {
        parse_headers = 1;
    }
#ifdef USE_SSL
    if (parse_headers || do_ssl)
#else /* USE_SSL */
    if (parse_headers)
#endif /* USE_SSL */
    {
        int p[2];
        int r;

        if (pipe (p) < 0) {
            send_error (500, "Internal Error", "", "Something unexpected went wrong making a pipe.");
        }
        r = fork();
        if (r < 0) {
            send_error (500, "Internal Error", "", "Something unexpected went wrong forking an interposer.");
        }
        if (r == 0) {
            /* Interposer process. */
            (void) close (p[1]);
            cgi_interpose_output (p[0], parse_headers);
            exit (0);
        }
        (void) close (p[0]);
        if (p[1] != STDOUT_FILENO) {
            (void) dup2 (p[1], STDOUT_FILENO);
        }
        if (p[1] != STDERR_FILENO) {
            (void) dup2 (p[1], STDERR_FILENO);
        }
        if (p[1] != STDOUT_FILENO && p[1] != STDERR_FILENO) {
            (void) close (p[1]);
        }
    } else {
        /* Otherwise, the request socket is stdout/stderr. */
        if (conn_fd != STDOUT_FILENO) {
            (void) dup2 (conn_fd, STDOUT_FILENO);
        }
        if (conn_fd != STDERR_FILENO) {
            (void) dup2 (conn_fd, STDERR_FILENO);
        }
    }

    /* At this point we would like to set conn_fd to be close-on-exec.
    ** Unfortunately there seems to be a Linux problem here - if we
    ** do this close-on-exec in Linux, the socket stays open but stderr
    ** gets closed - the last fd duped from the socket.  What a mess.
    ** So we'll just leave the socket as is, which under other OSs means
    ** an extra file descriptor gets passed to the child process.  Since
    ** the child probably already has that file open via stdin stdout
    ** and/or stderr, this is not a problem.
    */
    /* (void) fcntl( conn_fd, F_SETFD, 1 ); */

    /* Close the log file. */
    if (logfp != (FILE*) 0) {
        (void) fclose (logfp);
    }

    /* Close syslog. */
    closelog();

    /* Set priority. */
    (void) nice (CGI_NICE);

    /* Split the program into directory and binary, so we can chdir()
    ** to the program's own directory.  This isn't in the CGI 1.1
    ** spec, but it's what other HTTP servers do.
    */
    directory = e_strdup (file);
    binary = strrchr (directory, '/');
    if (binary == (char*) 0) {
        binary = file;
    } else {
        *binary++ = '\0';
        (void) chdir (directory);	/* ignore errors */
    }

    /* Default behavior for SIGPIPE. */
#ifdef HAVE_SIGSET
    (void) sigset (SIGPIPE, SIG_DFL);
#else /* HAVE_SIGSET */
    (void) signal (SIGPIPE, SIG_DFL);
#endif /* HAVE_SIGSET */

    /* Run the program. */
    (void) execve (binary, argp, envp);

    /* Something went wrong. */
    send_error (500, "Internal Error", "", "Something unexpected went wrong running a CGI program.");
}

/* This routine is used only for POST requests.  It reads the data
** from the request and sends it to the child process.  The only reason
** we need to do it this way instead of just letting the child read
** directly is that we have already read part of the data into our
** buffer.
**
** Oh, and it's also used for all SSL CGIs.
*/
void c_httpd::cgi_interpose_input (int wfd) {
    size_t c;
    ssize_t r, r2;
    char buf[1024];

    c = request_len - request_idx;
    if (c > 0) {
        if (write (wfd, & (request[request_idx]), c) != c)
            return;
    }
    while (c < content_length) {
        r = my_read (buf, MIN (sizeof (buf), content_length - c));
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            sleep (1);
            continue;
        }
        if (r <= 0)
            return;
        for (;;) {
            r2 = write (wfd, buf, r);
            if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep (1);
                continue;
            }
            if (r2 != r)
                return;
            break;
        }
        c += r;
    }
    post_post_garbage_hack();
}

/* Special hack to deal with broken browsers that send a LF or CRLF
** after POST data, causing TCP resets - we just read and discard up
** to 2 bytes.  Unfortunately this doesn't fix the problem for CGIs
** which avoid the interposer process due to their POST data being
** short.  Creating an interposer process for all POST CGIs is
** unacceptably expensive.
*/
void c_httpd::post_post_garbage_hack (void) {
    char buf[2];

#ifdef USE_SSL
    if (do_ssl)
        /* We don't need to do this for SSL, since the garbage has
        ** already been read.  Probably.
        */
        return;
#endif /* USE_SSL */

    set_ndelay (conn_fd);
    (void) read (conn_fd, buf, sizeof (buf));
    clear_ndelay (conn_fd);
}

/* This routine is used for parsed-header CGIs and for all SSL CGIs. */
void c_httpd::cgi_interpose_output (int rfd, int parse_headers) {
    ssize_t r, r2;
    char buf[1024];

    if (!parse_headers) {
        /* If we're not parsing headers, write out the default status line
        ** and proceed to the echo phase.
        */
        char http_head[] = "HTTP/1.0 200 OK\015\012";
        (void) my_write (http_head, sizeof (http_head));
    } else {
        /* Header parsing.  The idea here is that the CGI can return special
        ** headers such as "Status:" and "Location:" which change the return
        ** status of the response.  Since the return status has to be the very
        ** first line written out, we have to accumulate all the headers
        ** and check for the special ones before writing the status.  Then
        ** we write out the saved headers and proceed to echo the rest of
        ** the response.
        */
        size_t headers_size, headers_len;
        char* headers;
        char* br;
        int status;
        char* title;
        char* cp;

        /* Slurp in all headers. */
        headers_size = 0;
        add_to_buf (&headers, &headers_size, &headers_len, (char*) 0, 0);
        for (;;) {
            r = read (rfd, buf, sizeof (buf));
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep (1);
                continue;
            }
            if (r <= 0) {
                br = & (headers[headers_len]);
                break;
            }
            add_to_buf (&headers, &headers_size, &headers_len, buf, r);
            if ( (br = strstr (headers, "\015\012\015\012")) != (char*) 0 ||
                    (br = strstr (headers, "\012\012")) != (char*) 0)
                break;
        }

        /* If there were no headers, bail. */
        if (headers[0] == '\0')
            return;

        /* Figure out the status. */
        status = 200;
        if ( (cp = strstr (headers, "Status:")) != (char*) 0 &&
                cp < br &&
                (cp == headers || * (cp - 1) == '\012')) {
            cp += 7;
            cp += strspn (cp, " \t");
            status = atoi (cp);
        }
        if ( (cp = strstr (headers, "Location:")) != (char*) 0 &&
                cp < br &&
                (cp == headers || * (cp - 1) == '\012'))
            status = 302;

        /* Write the status line. */
        switch (status) {
        case 200:
            title = (char*) "OK";
            break;
        case 302:
            title = (char*) "Found";
            break;
        case 304:
            title = (char*) "Not Modified";
            break;
        case 400:
            title = (char*) "Bad Request";
            break;
        case 401:
            title = (char*) "Unauthorized";
            break;
        case 403:
            title = (char*) "Forbidden";
            break;
        case 404:
            title = (char*) "Not Found";
            break;
        case 408:
            title = (char*) "Request Timeout";
            break;
        case 500:
            title = (char*) "Internal Error";
            break;
        case 501:
            title = (char*) "Not Implemented";
            break;
        case 503:
            title = (char*) "Service Temporarily Overloaded";
            break;
        default:
            title = (char*) "Something";
            break;
        }
        (void) snprintf (
            buf, sizeof (buf), "HTTP/1.0 %d %s\015\012", status, title);
        (void) my_write (buf, strlen (buf));

        /* Write the saved headers. */
        (void) my_write (headers, headers_len);
    }

    /* Echo the rest of the output. */
    for (;;) {
        r = read (rfd, buf, sizeof (buf));
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            sleep (1);
            continue;
        }
        if (r <= 0)
            goto done;
        for (;;) {
            r2 = my_write (buf, r);
            if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep (1);
                continue;
            }
            if (r2 != r)
                goto done;
            break;
        }
    }
done:
    shutdown (conn_fd, SHUT_WR);
}

/* Set up CGI argument vector.  We don't have to worry about freeing
** stuff since we're a sub-process.  This gets done after make_envp() because
** we scribble on query.
*/
char ** c_httpd::make_argp (void) {
    char** argp;
    int argn;
    char* cp1;
    char* cp2;

    /* By allocating an arg slot for every character in the query, plus
    ** one for the filename and one for the NULL, we are guaranteed to
    ** have enough.  We could actually use strlen/2.
    */
    argp = (char**) malloc ( (strlen (query) + 2) * sizeof (char*));
    if (argp == (char**) 0)
        return (char**) 0;

    argp[0] = strrchr (file, '/');
    if (argp[0] != (char*) 0)
        ++argp[0];
    else
        argp[0] = file;

    argn = 1;

    printf ("make_argp::query:%s\n", query);

    /* According to the CGI spec at http://hoohoo.ncsa.uiuc.edu/cgi/cl.html,
    ** "The server should search the query information for a non-encoded =
    ** character to determine if the command line is to be used, if it finds
    ** one, the command line is not to be used."
    */
    //if (strchr (query, '=') == (char*) 0)
    {
        for (cp1 = cp2 = query; *cp2 != '\0'; ++cp2) {
            //if (*cp2 == '+')
            if (*cp2 == '+' || *cp2 == '&') {
                *cp2 = '\0';
                strdecode (cp1, cp1);
                argp[argn++] = cp1;
                cp1 = cp2 + 1;
            }
        }
        if (cp2 != cp1) {
            strdecode (cp1, cp1);
            argp[argn++] = cp1;
        }
    }

    argp[argn] = (char*) 0;
    return argp;
}

/* Set up CGI environment variables. Be real careful here to avoid
** letting malicious clients overrun a buffer.  We don't have
** to worry about freeing stuff since we're a sub-process.
*/
char ** c_httpd::make_envp (void) {
    static char* envp[55];
    int envn;
    char* cp;
    char buf[256];

    envn = 0;
    envp[envn++] = build_env ("PATH=%s", CGI_PATH);
    envp[envn++] = build_env ("LD_LIBRARY_PATH=%s", CGI_LD_LIBRARY_PATH);
    envp[envn++] = build_env ("SERVER_SOFTWARE=%s", SERVER_SOFTWARE);
    if (! bbvhost)
        cp = hostname;
    else
        cp = req_hostname;	/* already computed by virtual_file() */
    if (cp != (char*) 0)
        envp[envn++] = build_env ("SERVER_NAME=%s", cp);
    envp[envn++] = (char*) "GATEWAY_INTERFACE=CGI/1.1";
    envp[envn++] = (char*) "SERVER_PROTOCOL=HTTP/1.0";
    (void) snprintf (buf, sizeof (buf), "%d", (int) port);
    envp[envn++] = build_env ("SERVER_PORT=%s", buf);
    envp[envn++] = build_env (
                       "REQUEST_METHOD=%s", get_method_str (method));
    envp[envn++] = build_env ("SCRIPT_NAME=%s", path);
    if (pathinfo != (char*) 0) {
        envp[envn++] = build_env ("PATH_INFO=/%s", pathinfo);
        (void) snprintf (buf, sizeof (buf), "%s%s", cwd, pathinfo);
        envp[envn++] = build_env ("PATH_TRANSLATED=%s", buf);
    }
    if (query[0] != '\0')
        envp[envn++] = build_env ("QUERY_STRING=%s", query);
    envp[envn++] = build_env ("REMOTE_ADDR=%s", ntoa (&client_addr));
    if (referer[0] != '\0')
        envp[envn++] = build_env ("HTTP_REFERER=%s", referer);
    if (useragent[0] != '\0')
        envp[envn++] = build_env ("HTTP_USER_AGENT=%s", useragent);
    if (cookie != (char*) 0)
        envp[envn++] = build_env ("HTTP_COOKIE=%s", cookie);
    if (host != (char*) 0)
        envp[envn++] = build_env ("HTTP_HOST=%s", host);
    if (content_type != (char*) 0)
        envp[envn++] = build_env ("CONTENT_TYPE=%s", content_type);
    if (content_length != -1) {
        (void) snprintf (
            buf, sizeof (buf), "%lu", (unsigned long) content_length);
        envp[envn++] = build_env ("CONTENT_LENGTH=%s", buf);
    }
    if (remoteuser != (char*) 0)
        envp[envn++] = build_env ("REMOTE_USER=%s", remoteuser);
    if (authorization != (char*) 0)
        envp[envn++] = build_env ("AUTH_TYPE=%s", "Basic");
    if (getenv ("TZ") != (char*) 0)
        envp[envn++] = build_env ("TZ=%s", getenv ("TZ"));

    envp[envn] = (char*) 0;
    return envp;
}

char * c_httpd::build_env (const char* fmt, const char* arg) {
    char* cp;
    int size;
    char* buf;
    int maxbuf = 0;

    size = strlen (fmt) + strlen (arg);
    if (size > maxbuf) {
        if (maxbuf == 0) {
            maxbuf = MAX (200, size + 100);
            buf = (char*) e_malloc (maxbuf);
        } else {
            maxbuf = MAX (maxbuf * 2, size * 5 / 4);
            buf = (char*) e_realloc ( (void*) buf, maxbuf);
        }
    }
    (void) snprintf (buf, maxbuf, fmt, arg);
    cp = e_strdup (buf);
    return cp;
}

void c_httpd::auth_check (char* dirname) {
    char authpath[10000];
    struct stat sb;
    char authinfo[500];
    char* authpass;
    char* colon;
    char line[10000];
    int l;
    FILE* fp;
    char* cryp;

    /* Construct auth filename. */
    if (dirname[strlen (dirname) - 1] == '/')
        (void) snprintf (authpath, sizeof (authpath), "%s%s", dirname, AUTH_FILE);
    else
        (void) snprintf (authpath, sizeof (authpath), "%s/%s", dirname, AUTH_FILE);

    /* Does this directory have an auth file? */
    if (stat (authpath, &sb) < 0)
        /* Nope, let the request go through. */
        return;

    /* Does this request contain authorization info? */
    if (authorization == (char*) 0)
        /* Nope, return a 401 Unauthorized. */
        send_authenticate (dirname);

    /* Basic authorization info? */
    if (strncmp (authorization, "Basic ", 6) != 0)
        send_authenticate (dirname);

    /* Decode it. */
    l = b64_decode (
            & (authorization[6]), (unsigned char*) authinfo, sizeof (authinfo) - 1);
    authinfo[l] = '\0';
    /* Split into user and password. */
    authpass = strchr (authinfo, ':');
    if (authpass == (char*) 0)
        /* No colon?  Bogus auth info. */
        send_authenticate (dirname);
    *authpass++ = '\0';
    /* If there are more fields, cut them off. */
    colon = strchr (authpass, ':');
    if (colon != (char*) 0)
        *colon = '\0';

    /* Open the password file. */
    fp = fopen (authpath, "r");
    if (fp == (FILE*) 0) {
        /* The file exists but we can't open it?  Disallow access. */
        syslog (
            LOG_ERR, "%.80s auth file %.80s could not be opened - %m",
            ntoa (&client_addr), authpath);
        send_error (403, "Forbidden", "", "File is protected.");
    }

    /* Read it. */
    while (fgets (line, sizeof (line), fp) != (char*) 0) {
        /* Nuke newline. */
        l = strlen (line);
        if (line[l - 1] == '\n')
            line[l - 1] = '\0';
        /* Split into user and encrypted password. */
        cryp = strchr (line, ':');
        if (cryp == (char*) 0)
            continue;
        *cryp++ = '\0';
        /* Is this the right user? */
        if (strcmp (line, authinfo) == 0) {
            /* Yes. */
            (void) fclose (fp);
            /* So is the password right? */
            if (strcmp (crypt (authpass, cryp), cryp) == 0) {
                /* Ok! */
                remoteuser = line;
                return;
            } else
                /* No. */
                send_authenticate (dirname);
        }
    }

    /* Didn't find that user.  Access denied. */
    (void) fclose (fp);
    send_authenticate (dirname);
}

void c_httpd::send_authenticate (char* realm) {
    char header[10000];

    (void) snprintf (
        header, sizeof (header), "WWW-Authenticate: Basic realm=\"%s\"", realm);
    send_error (401, "Unauthorized", header, "Authorization required.");
}

char * c_httpd::virtual_file (char* file) {
    char* cp;
    static char vfile[10000];

    /* Use the request's hostname, or fall back on the IP address. */
    if (host != (char*) 0)
        req_hostname = host;
    else {
        usockaddr usa;
        int sz = sizeof (usa);
        if (getsockname (conn_fd, &usa.sa, (socklen_t*) &sz) < 0)
            req_hostname = (char*) "UNKNOWN_HOST";
        else
            req_hostname = ntoa (&usa);
    }
    /* Pound it to lower case. */
    for (cp = req_hostname; *cp != '\0'; ++cp) {
        if (isupper (*cp))
            *cp = tolower (*cp);
    }
    (void) snprintf (vfile, sizeof (vfile), "%s/%s", req_hostname, file);
    return vfile;
}

void c_httpd::send_error (int s, const char* title, const char* extra_header, const char* text) {
    
    file = (char*) "./index.html";
    stat (file, &sb);
    do_file();
    return;

    //XXX
    add_headers (
        s, title, extra_header, "", "text/html; charset=%s", (off_t) - 1, (time_t) - 1);

    send_error_body (s, title, text);

    send_error_tail();

    send_response();

#ifdef USE_SSL
    SSL_free (ssl);
#endif /* USE_SSL */
    exit (1);
}

void c_httpd::send_error_body (int s, const char* title, const char* text) {
    char filename[1000];
    char buf[10000];
    int buflen;

    if (bbvhost && req_hostname != (char*) 0) {
        /* Try virtual-host custom error page. */
        (void) snprintf (
            filename, sizeof (filename), "%s/%s/err%d.html",
            req_hostname, ERR_DIR, s);
        if (send_error_file (filename))
            return;
    }

    /* Try server-wide custom error page. */
    (void) snprintf (
        filename, sizeof (filename), "%s/err%d.html", ERR_DIR, s);
    if (send_error_file (filename))
        return;

    /* Send built-in error page. */
    buflen = snprintf (
                 buf, sizeof (buf), "\
<HTML>\n\
<HEAD><TITLE>%d %s</TITLE></HEAD>\n\
<BODY BGCOLOR=\"#cc9999\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
<H4>%d %s</H4>\n",
                 s, title, s, title);
    add_to_response (buf, buflen);
    buflen = snprintf (buf, sizeof (buf), "%s\n", text);
    add_to_response (buf, buflen);
}

int c_httpd::send_error_file (char* filename) {
    FILE* fp;
    char buf[1000];
    size_t r;

    fp = fopen (filename, "r");
    if (fp == (FILE*) 0)
        return 0;
    for (;;) {
        r = fread (buf, 1, sizeof (buf), fp);
        if (r == 0)
            break;
        add_to_response (buf, r);
    }
    (void) fclose (fp);
    return 1;
}

void c_httpd::send_error_tail (void) {
    char buf[500];
    int buflen;

    if (match ("**MSIE**", useragent)) {
        int n;
        buflen = snprintf (buf, sizeof (buf), "<!--\n");
        add_to_response (buf, buflen);
        for (n = 0; n < 6; ++n) {
            buflen = snprintf (buf, sizeof (buf), "Padding so that MSIE deigns to show this error instead of its own canned one.\n");
            add_to_response (buf, buflen);
        }
        buflen = snprintf (buf, sizeof (buf), "-->\n");
        add_to_response (buf, buflen);
    }

    buflen = snprintf (buf, sizeof (buf), "\
<HR>\n\
<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n\
</BODY>\n\
</HTML>\n",
                       SERVER_URL, SERVER_SOFTWARE);
    add_to_response (buf, buflen);
}

void c_httpd::add_headers (int s,
                           const char* title,
                           const char* extra_header,
                           const char* me,
                           const char* mt,
                           off_t b,
                           time_t mod) {
    time_t now, expires;
    char timebuf[100];
    char buf[10000];
    int buflen;
    int s100;
    const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";

    status = s;
    bytes = b;
    make_log_entry();
    start_response();
    buflen = snprintf (buf, sizeof (buf), "%s %d %s\015\012", protocol, status, title);
    add_to_response (buf, buflen);
    buflen = snprintf (buf, sizeof (buf), "Server: %s\015\012", SERVER_SOFTWARE);
    add_to_response (buf, buflen);
    now = time ( (time_t*) 0);
    (void) strftime (timebuf, sizeof (timebuf), rfc1123_fmt, gmtime (&now));
    buflen = snprintf (buf, sizeof (buf), "Date: %s\015\012", timebuf);
    add_to_response (buf, buflen);
    s100 = status / 100;
    if (s100 != 2 && s100 != 3) {
        buflen = snprintf (buf, sizeof (buf), "Cache-Control: no-cache,no-store\015\012");
        add_to_response (buf, buflen);
    }
    if (extra_header != (char*) 0 && extra_header[0] != '\0') {
        buflen = snprintf (buf, sizeof (buf), "%s\015\012", extra_header);
        add_to_response (buf, buflen);
    }
    if (me != (char*) 0 && me[0] != '\0') {
        buflen = snprintf (buf, sizeof (buf), "Content-Encoding: %s\015\012", me);
        add_to_response (buf, buflen);
    }
    if (mt != (char*) 0 && mt[0] != '\0') {
        buflen = snprintf (buf, sizeof (buf), "Content-Type: %s\015\012", mt);
        add_to_response (buf, buflen);
    }
    if (bytes >= 0) {
        buflen = snprintf (
                     buf, sizeof (buf), "Content-Length: %ld\015\012", (int64_t) bytes);
        add_to_response (buf, buflen);
    }
    if (p3p != (char*) 0 && p3p[0] != '\0') {
        buflen = snprintf (buf, sizeof (buf), "P3P: %s\015\012", p3p);
        add_to_response (buf, buflen);
    }
    if (max_age >= 0) {
        expires = now + max_age;
        (void) strftime (
            timebuf, sizeof (timebuf), rfc1123_fmt, gmtime (&expires));
        buflen = snprintf (buf, sizeof (buf),
                           "Cache-Control: max-age=%d\015\012Expires: %s\015\012", max_age, timebuf);
        add_to_response (buf, buflen);
    }
    if (mod != (time_t) - 1) {
        (void) strftime (
            timebuf, sizeof (timebuf), rfc1123_fmt, gmtime (&mod));
        buflen = snprintf (buf, sizeof (buf), "Last-Modified: %s\015\012", timebuf);
        add_to_response (buf, buflen);
    }
    buflen = snprintf (buf, sizeof (buf), "Connection: close\015\012\015\012");
    add_to_response (buf, buflen);
}

void c_httpd::start_request (void) {
    request_size = 0;
    request_idx = 0;
    request_bk_size = 0;
    request_bk_idx = 0;
}

void c_httpd::add_to_request (char* str, size_t len) {
    add_to_buf (&request, &request_size, &request_len, str, len);
}

void c_httpd::add_to_request_xh (char* str, size_t len) {
    add_to_buf (&request_bk, &request_bk_size, &request_bk_len, str, len);
}

char * c_httpd::get_request_line (void) {
    int i;
    char c;

    for (i = request_idx; request_idx < request_len; ++request_idx) {
        c = request[request_idx];
        if (c == '\012' || c == '\015') {
            request[request_idx] = '\0';
            ++request_idx;
            if (c == '\015'
                    && request_idx < request_len
                    && request[request_idx] == '\012') {
                request[request_idx] = '\0';
                ++request_idx;
            }
            return & (request[i]);
        }
    }
    return (char*) 0;
}

void c_httpd::start_response (void) {
    response_size = 0;
}

void c_httpd::add_to_response (char* str, size_t len) {
    add_to_buf (&response, &response_size, &response_len, str, len);
}

void c_httpd::send_response (void) {
    (void) my_write (response, response_len);
}

void c_httpd::send_via_write (int fd, off_t size) {
    if (size <= SIZE_T_MAX) {
        size_t size_size = (size_t) size;
        void* ptr = mmap (0, size_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (ptr != (void*) - 1) {
            (void) my_write ( (char*) ptr, size_size);
            (void) munmap (ptr, size_size);
        }
#ifdef MADV_SEQUENTIAL
        /* If we have madvise, might as well call it.  Although sequential
        ** access is probably already the default.
        */
        (void) madvise (ptr, size_size, MADV_SEQUENTIAL);
#endif /* MADV_SEQUENTIAL */
    } else {
        /* mmap can't deal with files larger than 2GB. */
        char buf[30000];
        ssize_t r, r2;

        for (;;) {
            r = read (fd, buf, sizeof (buf));
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep (1);
                continue;
            }
            if (r <= 0)
                return;
            for (;;) {
                r2 = my_write (buf, r);
                if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                    sleep (1);
                    continue;
                }
                if (r2 != r)
                    return;
                break;
            }
        }
    }
}

ssize_t c_httpd::my_read (char* buf, size_t size) {
#ifdef USE_SSL
    if (do_ssl) {
        return SSL_read (ssl, buf, size);
    } else {
        return read (conn_fd, buf, size);
    }
#else /* USE_SSL */
    return read (conn_fd, buf, size);
#endif /* USE_SSL */
}

ssize_t c_httpd::my_write (char* buf, size_t size) {
#ifdef USE_SSL
    if (do_ssl) {
        return SSL_write (ssl, buf, size);
    } else {
        return write (conn_fd, buf, size);
    }
#else /* USE_SSL */
    return write (conn_fd, buf, size);
#endif /* USE_SSL */
}

#ifdef HAVE_SENDFILE
int c_httpd::my_sendfile (int fd, int socket, off_t offset, size_t nbytes) {
#ifdef HAVE_LINUX_SENDFILE
    off_t lo = offset;
    return sendfile (socket, fd, &lo, nbytes);
#else /* HAVE_LINUX_SENDFILE */
    return sendfile (fd, socket, offset, nbytes, (struct sf_hdtr*) 0, (off_t*) 0, 0);
#endif /* HAVE_LINUX_SENDFILE */
}
#endif /* HAVE_SENDFILE */

void c_httpd::add_to_buf (char** bufP,
                          size_t* bufsizeP,
                          size_t* buflenP,
                          char* str,
                          size_t len) {
    if (*bufsizeP == 0) {
        *bufsizeP = len + 500;
        *buflenP = 0;
        *bufP = (char*) e_malloc (*bufsizeP);
    } else if (*buflenP + len >= *bufsizeP) {
        *bufsizeP = *buflenP + len + 500;
        *bufP = (char*) e_realloc ( (void*) * bufP, *bufsizeP);
    }
    (void) memmove (& ( (*bufP) [*buflenP]), str, len);
    *buflenP += len;
    (*bufP) [*buflenP] = '\0';
}

void c_httpd::make_log_entry (void) {
    char* ru;
    char url[500];
    char bytes_str[40];
    time_t now;
    struct tm* t;
    const char* cernfmt_nozone = "%d/%b/%Y:%H:%M:%S";
    char date_nozone[100];
    int zone;
    char sign;
    char date[100];

    if (logfp == (FILE*) 0) {
        return;
    }

    /* Fill in some null values. */
    if (protocol == (char*) 0) {
        protocol = (char*) "UNKNOWN";
    }
    if (path == (char*) 0) {
        path = (char*) "";
    }
    if (req_hostname == (char*) 0) {
        req_hostname = hostname;
    }

    /* Format the user. */
    if (remoteuser != (char*) 0) {
        ru = remoteuser;
    } else {
        ru = (char*) "-";
    }
    now = time ( (time_t*) 0);
    /* If we're vhosting, prepend the hostname to the url.  This is
    ** a little weird, perhaps writing separate log files for
    ** each vhost would make more sense.
    */
    if (bbvhost) {
        (void) snprintf (url, sizeof (url), "/%s%s", req_hostname, path);
    } else {
        (void) snprintf (url, sizeof (url), "%s", path);
    }
    /* Format the bytes. */
    if (bytes >= 0) {
        (void) snprintf (
            bytes_str, sizeof (bytes_str), "%ld", (int64_t) bytes);
    } else {
        (void) strcpy (bytes_str, "-");
    }
    /* Format the time, forcing a numeric timezone (some log analyzers
    ** are stoooopid about this).
    */
    t = localtime (&now);
    (void) strftime (date_nozone, sizeof (date_nozone), cernfmt_nozone, t);
#ifdef HAVE_TM_GMTOFF
    zone = t->tm_gmtoff / 60L;
#else
    zone = - (timezone / 60L);
    /* Probably have to add something about daylight time here. */
#endif
    if (zone >= 0) {
        sign = '+';
    } else {
        sign = '-';
        zone = -zone;
    }
    zone = (zone / 60) * 100 + zone % 60;
    (void) snprintf (date, sizeof (date), "%s %c%04d", date_nozone, sign, zone);
    /* And write the log entry. */
    (void) fprintf (logfp,
                    "%.80s - %.80s [%s] \"%.80s %.200s %.80s\" %d %s \"%.200s\" \"%.200s\"\n",
                    ntoa (&client_addr), ru, date, get_method_str (method), url,
                    protocol, status, bytes_str, referer, useragent);
    (void) fflush (logfp);
}

/* Returns if it's ok to serve the url, otherwise generates an error
** and exits.
*/
void c_httpd::check_referer (void) {
    char* cp;

    /* Are we doing referer checking at all? */
    if (url_pattern == (char*) 0) {
        return;
    }

    /* Is it ok? */
    if (really_check_referer()) {
        return;
    }

    /* Lose. */
    if (bbvhost && req_hostname != (char*) 0) {
        cp = req_hostname;
    } else {
        cp = hostname;
    }
    if (cp == (char*) 0) {
        cp = (char*) "";
    }
    syslog (
        LOG_INFO, "%.80s non-local referer \"%.80s%.80s\" \"%.80s\"",
        ntoa (&client_addr), cp, path, referer);
    send_error (403, "Forbidden", "", "You must supply a local referer.");
}

/* Returns 1 if ok to serve the url, 0 if not. */
int c_httpd::really_check_referer (void) {
    char* cp1;
    char* cp2;
    char* cp3;
    char* refhost;
    char *lp;

    /* Check for an empty referer. */
    if (referer == (char*) 0 || referer[0] == '\0' ||
            (cp1 = strstr (referer, "//")) == (char*) 0) {
        /* Disallow if we require a referer and the url matches. */
        if (no_empty_referers && match (url_pattern, path))
            return 0;
        /* Otherwise ok. */
        return 1;
    }

    /* Extract referer host. */
    cp1 += 2;
    for (cp2 = cp1; *cp2 != '/' && *cp2 != ':' && *cp2 != '\0'; ++cp2) {
        continue;
    }
    refhost = (char*) e_malloc (cp2 - cp1 + 1);
    for (cp3 = refhost; cp1 < cp2; ++cp1, ++cp3) {
        if (isupper (*cp1)) {
            *cp3 = tolower (*cp1);
        } else {
            *cp3 = *cp1;
        }
    }
    *cp3 = '\0';

    /* Local pattern? */
    if (local_pattern != (char*) 0) {
        lp = local_pattern;
    } else {
        /* No local pattern.  What's our hostname? */
        if (! bbvhost) {
            /* Not vhosting, use the server name. */
            lp = hostname;
            if (lp == (char*) 0) {
                /* Couldn't figure out local hostname - give up. */
                return 1;
            }
        } else {
            /* We are vhosting, use the hostname on this connection. */
            lp = req_hostname;
            if (lp == (char*) 0) {
                /* Oops, no hostname.  Maybe it's an old browser that
                ** doesn't send a Host: header.  We could figure out
                ** the default hostname for this IP address, but it's
                ** not worth it for the few requests like this.
                */
                return 1;
            }
        }
    }

    /* If the referer host doesn't match the local host pattern, and
    ** the URL does match the url pattern, it's an illegal reference.
    */
    if (! match (lp, refhost) && match (url_pattern, path)) {
        return 0;
    }
    /* Otherwise ok. */
    return 1;
}

char * c_httpd::get_method_str (int m) {
    switch (m) {
    case METHOD_GET:
        return (char*) "GET";
    case METHOD_HEAD:
        return (char*) "HEAD";
    case METHOD_POST:
        return (char*) "POST";
    default:
        return (char*) "UNKNOWN";
    }
}

/* qsort comparison routine - declared old-style on purpose, for portability. */
int c_httpd::ext_compare (const void * a, const void * b) {
    return strcmp ( ( (struct mime_entry*) a)->ext, ( (struct mime_entry*) b)->ext);
}

void c_httpd::init_mime (void) {
    int i;

    /* Sort the tables so we can do binary search. */
    //qsort ( (void*) enc_tab, (size_t) n_enc_tab, sizeof (*enc_tab), ext_compare);
    //qsort ( (void*) typ_tab, (size_t) n_typ_tab, sizeof (*typ_tab), ext_compare);

    /* Fill in the lengths. */
    for (i = 0; i < n_enc_tab; ++i) {
        enc_tab[i].ext_len = strlen (enc_tab[i].ext);
        enc_tab[i].val_len = strlen (enc_tab[i].val);
    }
    for (i = 0; i < n_typ_tab; ++i) {
        typ_tab[i].ext_len = strlen (typ_tab[i].ext);
        typ_tab[i].val_len = strlen (typ_tab[i].val);
    }
}

/* Figure out MIME encodings and type based on the filename.  Multiple
** encodings are separated by commas, and are listed in the order in
** which they were applied to the file.
*/
const char * c_httpd::figure_mime (char* name, char* me, size_t me_size) {
    char* prev_dot;
    char* dot;
    char* ext;
    int me_indexes[100], n_me_indexes;
    size_t ext_len, me_len;
    int i, top, bot, mid;
    int r;
    const char* default_type = "text/plain; charset=%s";
    const char* type;

    /* Peel off encoding extensions until there aren't any more. */
    n_me_indexes = 0;
    for (prev_dot = &name[strlen (name)]; ; prev_dot = dot) {
        for (dot = prev_dot - 1; dot >= name && *dot != '.'; --dot) {
            ;
        }
        if (dot < name) {
            /* No dot found.  No more encoding extensions, and no type
            ** extension either.
            */
            type = default_type;
            goto done;
        }
        ext = dot + 1;
        ext_len = prev_dot - ext;
        /* Search the encodings table.  Linear search is fine here, there
        ** are only a few entries.
        */
        for (i = 0; i < n_enc_tab; ++i) {
            if (ext_len == enc_tab[i].ext_len && strncasecmp (ext, enc_tab[i].ext, ext_len) == 0) {
                if (n_me_indexes < sizeof (me_indexes) / sizeof (*me_indexes)) {
                    me_indexes[n_me_indexes] = i;
                    ++n_me_indexes;
                }
                goto next;
            }
        }
        /* No encoding extension found.  Break and look for a type extension. */
        break;

next:
        ;
    }

    /* Binary search for a matching type extension. */
    top = n_typ_tab - 1;
    bot = 0;
    while (top >= bot) {
        mid = (top + bot) / 2;
        r = strncasecmp (ext, typ_tab[mid].ext, ext_len);
        if (r < 0)
            top = mid - 1;
        else if (r > 0)
            bot = mid + 1;
        else if (ext_len < typ_tab[mid].ext_len)
            top = mid - 1;
        else if (ext_len > typ_tab[mid].ext_len)
            bot = mid + 1;
        else {
            type = typ_tab[mid].val;
            goto done;
        }
    }
    type = default_type;

done:

    /* The last thing we do is actually generate the mime-encoding header. */
    me[0] = '\0';
    me_len = 0;
    for (i = n_me_indexes - 1; i >= 0; --i) {
        if (me_len + enc_tab[me_indexes[i]].val_len + 1 < me_size) {
            if (me[0] != '\0') {
                (void) strcpy (&me[me_len], ",");
                ++me_len;
            }
            (void) strcpy (&me[me_len], enc_tab[me_indexes[i]].val);
            me_len += enc_tab[me_indexes[i]].val_len;
        }
    }

    return type;
}

void c_httpd::re_open_logfile (void) {
    if (logfp != (FILE*) 0) {
        (void) fclose (logfp);
        logfp = (FILE*) 0;
    }
    if (logfile != (char*) 0) {
        syslog (LOG_NOTICE, "re-opening logfile");
        logfp = fopen (logfile, "a");
        if (logfp == (FILE*) 0) {
            syslog (LOG_CRIT, "%s - %m", logfile);
            perror (logfile);
            exit (1);
        }
    }
}

void c_httpd::handle_write_timeout (int sig) {
    syslog (LOG_INFO, "%.80s connection timed out writing", ntoa (&client_addr));
    exit (1);
}

void c_httpd::lookup_hostname (usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P) {
#ifdef USE_IPV6
    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv6;
    struct addrinfo* aiv4;

    (void) memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf (portstr, sizeof (portstr), "%d", (int) port);
    if ( (gaierr = getaddrinfo (hostname, portstr, &hints, &ai)) != 0) {
        syslog (
            LOG_CRIT, "getaddrinfo %.80s - %s", hostname,
            gai_strerror (gaierr));
        (void) fprintf (
            stderr, "%s: getaddrinfo %.80s - %s\n", "BBDog", hostname,
            gai_strerror (gaierr));
        exit (1);
    }

    /* Find the first IPv6 and IPv4 entries. */
    aiv6 = (struct addrinfo*) 0;
    aiv4 = (struct addrinfo*) 0;
    for (ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next) {
        switch (ai2->ai_family) {
        case AF_INET6:
            if (aiv6 == (struct addrinfo*) 0)
                aiv6 = ai2;
            break;
        case AF_INET:
            if (aiv4 == (struct addrinfo*) 0)
                aiv4 = ai2;
            break;
        }
    }

    if (aiv6 == (struct addrinfo*) 0)
        *gotv6P = 0;
    else {
        if (sa6_len < aiv6->ai_addrlen) {
            syslog (
                LOG_CRIT, "%.80s - sockaddr too small (%lu < %lu)",
                hostname, (unsigned long) sa6_len,
                (unsigned long) aiv6->ai_addrlen);
            (void) fprintf (
                stderr, "%s: %.80s - sockaddr too small (%lu < %lu)\n",
                "BBDog", hostname, (unsigned long) sa6_len,
                (unsigned long) aiv6->ai_addrlen);
            exit (1);
        }
        (void) memset (usa6P, 0, sa6_len);
        (void) memmove (usa6P, aiv6->ai_addr, aiv6->ai_addrlen);
        *gotv6P = 1;
    }

    if (aiv4 == (struct addrinfo*) 0)
        *gotv4P = 0;
    else {
        if (sa4_len < aiv4->ai_addrlen) {
            syslog (
                LOG_CRIT, "%.80s - sockaddr too small (%lu < %lu)",
                hostname, (unsigned long) sa4_len,
                (unsigned long) aiv4->ai_addrlen);
            (void) fprintf (
                stderr, "%s: %.80s - sockaddr too small (%lu < %lu)\n",
                "BBDog", hostname, (unsigned long) sa4_len,
                (unsigned long) aiv4->ai_addrlen);
            exit (1);
        }
        (void) memset (usa4P, 0, sa4_len);
        (void) memmove (usa4P, aiv4->ai_addr, aiv4->ai_addrlen);
        *gotv4P = 1;
    }

    freeaddrinfo (ai);

#else /* USE_IPV6 */

    struct hostent* he;

    *gotv6P = 0;

    (void) memset (usa4P, 0, sa4_len);
    usa4P->sa.sa_family = AF_INET;
    if (hostname == (char*) 0)
        usa4P->sa_in.sin_addr.s_addr = htonl (INADDR_ANY);
    else {
        usa4P->sa_in.sin_addr.s_addr = inet_addr (hostname);
        if ( (int) usa4P->sa_in.sin_addr.s_addr == -1) {
            he = gethostbyname (hostname);
            if (he == (struct hostent*) 0) {
#ifdef HAVE_HSTRERROR
                syslog (
                    LOG_CRIT, "gethostbyname %.80s - %s", hostname,
                    hstrerror (h_errno));
                (void) fprintf (
                    stderr, "%s: gethostbyname %.80s - %s\n", "BBDog", hostname,
                    hstrerror (h_errno));
#else /* HAVE_HSTRERROR */
                syslog (LOG_CRIT, "gethostbyname %.80s failed", hostname);
                (void) fprintf (
                    stderr, "%s: gethostbyname %.80s failed\n", "BBDog",
                    hostname);
#endif /* HAVE_HSTRERROR */
                exit (1);
            }
            if (he->h_addrtype != AF_INET) {
                syslog (LOG_CRIT, "%.80s - non-IP network address", hostname);
                (void) fprintf (
                    stderr, "%s: %.80s - non-IP network address\n", "BBDog",
                    hostname);
                exit (1);
            }
            (void) memmove (
                &usa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length);
        }
    }
    usa4P->sa_in.sin_port = htons (port);
    *gotv4P = 1;

#endif /* USE_IPV6 */
}

char * c_httpd::ntoa (usockaddr* usaP) {
#ifdef USE_IPV6
    static char str[200];

    if (getnameinfo (&usaP->sa, sockaddr_len (usaP), str, sizeof (str), 0, 0, NI_NUMERICHOST) != 0) {
        str[0] = '?';
        str[1] = '\0';
    } else if (IN6_IS_ADDR_V4MAPPED (&usaP->sa_in6.sin6_addr) && strncmp (str, "::ffff:", 7) == 0)
        /* Elide IPv6ish prefix for IPv4 addresses. */
        (void) strcpy (str, &str[7]);

    return str;

#else /* USE_IPV6 */

    return inet_ntoa (usaP->sa_in.sin_addr);

#endif /* USE_IPV6 */
}

int c_httpd::sockaddr_check (usockaddr* usaP) {
    switch (usaP->sa.sa_family) {
    case AF_INET:
        return 1;
#ifdef USE_IPV6
    case AF_INET6:
        return 1;
#endif /* USE_IPV6 */
    default:
        return 0;
    }
}

size_t c_httpd::sockaddr_len (usockaddr* usaP) {
    switch (usaP->sa.sa_family) {
    case AF_INET:
        return sizeof (struct sockaddr_in);
#ifdef USE_IPV6
    case AF_INET6:
        return sizeof (struct sockaddr_in6);
#endif /* USE_IPV6 */
    default:
        return 0;	/* shouldn't happen */
    }
}

/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
void c_httpd::strdecode (char* to, char* from) {
    for (; *from != '\0'; ++to, ++from) {
        if (from[0] == '%' && isxdigit (from[1]) && isxdigit (from[2])) {
            *to = hexit (from[1]) * 16 + hexit (from[2]);
            from += 2;
        } else
            *to = *from;
    }
    *to = '\0';
}

int c_httpd::hexit (char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;           /* shouldn't happen, we're guarded by isxdigit() */
}



/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
int c_httpd::b64_decode (const char* str, unsigned char* space, int size) {
    const char* cp;
    int space_idx, phase;
    int d, prev_d = 0;
    unsigned char c;

    space_idx = 0;
    phase = 0;
    for (cp = str; *cp != '\0'; ++cp) {
        d = b64_decode_table[ (int) * cp];
        if (d != -1) {
            switch (phase) {
            case 0:
                ++phase;
                break;
            case 1:
                c = ( (prev_d << 2) | ( (d & 0x30) >> 4));
                if (space_idx < size)
                    space[space_idx++] = c;
                ++phase;
                break;
            case 2:
                c = ( ( (prev_d & 0xf) << 4) | ( (d & 0x3c) >> 2));
                if (space_idx < size)
                    space[space_idx++] = c;
                ++phase;
                break;
            case 3:
                c = ( ( (prev_d & 0x03) << 6) | d);
                if (space_idx < size)
                    space[space_idx++] = c;
                phase = 0;
                break;
            }
            prev_d = d;
        }
    }
    return space_idx;
}

/* Set NDELAY mode on a socket. */
void c_httpd::set_ndelay (int fd) {
    int flags, newflags;

    flags = fcntl (fd, F_GETFL, 0);
    if (flags != -1) {
        newflags = flags | (int) O_NDELAY;
        if (newflags != flags)
            (void) fcntl (fd, F_SETFL, newflags);
    }
}

/* Clear NDELAY mode on a socket. */
void c_httpd::clear_ndelay (int fd) {
    int flags, newflags;

    flags = fcntl (fd, F_GETFL, 0);
    if (flags != -1) {
        newflags = flags & ~ (int) O_NDELAY;
        if (newflags != flags)
            (void) fcntl (fd, F_SETFL, newflags);
    }
}

void * c_httpd::e_malloc (size_t size) {
    void* ptr;

    ptr = malloc (size);
    if (ptr == (void*) 0) {
        syslog (LOG_CRIT, "out of memory");
        (void) fprintf (stderr, "%s: out of memory\n", "BBDog");
        exit (1);
    }
    return ptr;
}

void * c_httpd::e_realloc (void* optr, size_t size) {
    void* ptr;

    ptr = realloc (optr, size);
    if (ptr == (void*) 0) {
        syslog (LOG_CRIT, "out of memory");
        (void) fprintf (stderr, "%s: out of memory\n", "BBDog");
        exit (1);
    }
    return ptr;
}

char * c_httpd::e_strdup (char* ostr) {

    char* str;

    str = strdup (ostr);
    if (str == (char*) 0) {
        syslog (LOG_CRIT, "out of memory copying a string");
        (void) fprintf (stderr, "%s: out of memory copying a string\n", "BBDog");
        exit (1);
    }
    return str;
}

#ifdef NO_SNPRINTF
/* Some systems don't have snprintf(), so we make our own that uses
** vsprintf().  This workaround is probably vulnerable to buffer overruns,
** so upgrade your OS!
*/
int c_httpd::snprintf (char* str, size_t size, const char* format, ...) {
    va_list ap;
    int r;

    va_start (ap, format);
    r = vsprintf (str, format, ap);
    va_end (ap);
    return r;
}
#endif /* NO_SNPRINTF */

int c_httpd::set_updata_path (const char *path) {
    int i = 0;
    while (1) {
        if ( (char*) 0 == envp[i])
            break;
        i++;
    }
    envp[i++] = build_env ("UPDATA_PATH=%s", path);
    envp[i] = (char*) 0;
}

int c_httpd::set_updata_name (const char *name) {
    int i = 0;
    while (1) {
        if ( (char*) 0 == envp[i])
            break;
        i++;
    }
    envp[i++] = build_env ("UPDATA_NAME=%s", name);
    envp[i] = (char*) 0;
}

/*
 * strlcpy - like strcpy/strncpy, doesn't overflow destination buffer,
 * always leaves destination null-terminated (for len > 0).
 */
size_t c_httpd::strlcpy (char *dest, const char *src, size_t len) {

    size_t ret = strlen (src);

    if (len != 0) {
        if (ret < len)
            strcpy (dest, src);
        else {
            strncpy (dest, src, len - 1);
            dest[len - 1] = 0;
        }
    }

    return ret;
}

/*
 * strlcat - like strcat/strncat, doesn't overflow destination buffer,
 * always leaves destination null-terminated (for len > 0).
 */
size_t c_httpd::strlcat (char *dest, const char *src, size_t len) {
    size_t dlen = strlen (dest);

    return dlen + strlcpy (dest + dlen, src, (len > dlen ? len - dlen : 0));
}

void * c_httpd::safe_malloc (size_t size) {
    void * retval = NULL;
    retval = malloc (size);
    if (!retval) {
        printf ("Failed to malloc %ld bytes of memory: %s.  Bailing out", size, strerror (errno));
        exit (1);
    }
    return (retval);
}

char * c_httpd::safe_strdup (const char *s) {
    char * retval = NULL;
    if (!s) {
        printf ("safe_strdup called with NULL which would have crashed strdup. Bailing out");
        exit (1);
    }
    retval = strdup (s);
    if (!retval) {
        printf ("Failed to duplicate a string: %s.  Bailing out", strerror (errno));
        exit (1);
    }
    return (retval);
}

int c_httpd::safe_asprintf (char **strp, const char *fmt, ...) {
    va_list ap;
    int retval;

    va_start (ap, fmt);
    retval = safe_vasprintf (strp, fmt, ap);
    va_end (ap);

    return (retval);
}

int c_httpd::safe_vasprintf (char **strp, const char *fmt, va_list ap) {
    int retval;

    retval = vasprintf (strp, fmt, ap);

    if (retval == -1) {
        printf ("Failed to vasprintf: %s.  Bailing out", strerror (errno));
        exit (1);
    }
    return (retval);
}

/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char* c_httpd::arp_get (const char *req_ip) {
    FILE *proc;
    char ip[16];
    char mac[18];
    char *reply = NULL;

    if (! (proc = fopen ("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
    while (!feof (proc) && fgetc (proc) != '\n');

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof (proc) &&
            (fscanf (proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strcmp (ip, req_ip) == 0) {
            reply = safe_strdup (mac);
            break;
        }
    }

    fclose (proc);
    return reply;
}

int c_httpd::match (const char* pattern, const char* string) {
    const char* my_or;
    for (;;) {
        my_or = strchr (pattern, '|');
        if (my_or == (char*) 0)
            return match_one (pattern, strlen (pattern), string);
        if (match_one (pattern, my_or - pattern, string))
            return 1;
        pattern = my_or + 1;
    }
}

int c_httpd::match_one (const char* pattern, int patternlen, const char* string) {
    const char* p;

    for (p = pattern; p - pattern < patternlen; ++p, ++string) {
        if (*p == '?' && *string != '\0')
            continue;
        if (*p == '*') {
            int i, pl;
            ++p;
            if (*p == '*') {
                /* Double-wildcard matches anything. */
                ++p;
                i = strlen (string);
            } else
                /* Single-wildcard matches anything but slash. */
                i = strcspn (string, "/");
            pl = patternlen - (p - pattern);
            for (; i >= 0; --i)
                if (match_one (p, pl, & (string[i])))
                    return 1;
            return 0;
        }
        if (*p != *string)
            return 0;
    }
    if (*string == '\0')
        return 1;
    return 0;
}

void c_httpd::pound_case (char* str) {
    for (; *str != '\0'; ++str) {
        if (isupper ( (int) *str))
            *str = tolower ( (int) * str);
    }
}

static int strlong_compare (const void * v1, const void * v2) {
    return strcmp ( ( (struct strlong*) v1)->s, ( (struct strlong*) v2)->s);
}

int c_httpd::strlong_search (char* str, struct strlong* tab, int n, long* lP) {
    int i, h, l, r;

    l = 0;
    h = n - 1;
    for (;;) {
        i = (h + l) / 2;
        r = strcmp (str, tab[i].s);
        if (r < 0)
            h = i - 1;
        else if (r > 0)
            l = i + 1;
        else {
            *lP = tab[i].l;
            return 1;
        }
        if (h < l)
            return 0;
    }
}

int c_httpd::scan_wday (char* str_wday, long* tm_wdayP) {
    static struct strlong wday_tab[] = {
        { "sun", 0 }, { "sunday", 0 },
        { "mon", 1 }, { "monday", 1 },
        { "tue", 2 }, { "tuesday", 2 },
        { "wed", 3 }, { "wednesday", 3 },
        { "thu", 4 }, { "thursday", 4 },
        { "fri", 5 }, { "friday", 5 },
        { "sat", 6 }, { "saturday", 6 },
    };
    static int sorted = 0;

    if (! sorted) {
        (void) qsort ( (void*) wday_tab,
                       (size_t) sizeof (wday_tab) / sizeof (struct strlong),
                       (size_t) sizeof (struct strlong),
                       strlong_compare);
        sorted = 1;
    }
    pound_case (str_wday);
    return strlong_search (
               str_wday, wday_tab, sizeof (wday_tab) / sizeof (struct strlong), tm_wdayP);
}

int c_httpd::scan_mon (char* str_mon, long* tm_monP) {
    static struct strlong mon_tab[] = {
        { "jan", 0 }, { "january", 0 },
        { "feb", 1 }, { "february", 1 },
        { "mar", 2 }, { "march", 2 },
        { "apr", 3 }, { "april", 3 },
        { "may", 4 },
        { "jun", 5 }, { "june", 5 },
        { "jul", 6 }, { "july", 6 },
        { "aug", 7 }, { "august", 7 },
        { "sep", 8 }, { "september", 8 },
        { "oct", 9 }, { "october", 9 },
        { "nov", 10 }, { "november", 10 },
        { "dec", 11 }, { "december", 11 },
    };
    static int sorted = 0;

    if (! sorted) {
        (void) qsort (
            mon_tab, sizeof (mon_tab) / sizeof (struct strlong),
            sizeof (struct strlong), strlong_compare);
        sorted = 1;
    }
    pound_case (str_mon);
    return strlong_search (
               str_mon, mon_tab, sizeof (mon_tab) / sizeof (struct strlong), tm_monP);
}

int c_httpd::is_leap (int year) {
    return year % 400 ? (year % 100 ? (year % 4 ? 0 : 1) : 0) : 1;
}

/* Basically the same as mktime(). */
time_t c_httpd::tm_to_time (struct tm* tmP) {

    time_t t;
    static int monthtab[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };

    /* Years since epoch, converted to days. */
    t = (tmP->tm_year - 70) * 365;
    /* Leap days for previous years. */
    t += (tmP->tm_year - 69) / 4;
    /* Days for the beginning of this month. */
    t += monthtab[tmP->tm_mon];
    /* Leap day for this year. */
    if (tmP->tm_mon >= 2 && is_leap (tmP->tm_year + 1900))
        ++t;
    /* Days since the beginning of this month. */
    t += tmP->tm_mday - 1;	/* 1-based field */
    /* Hours, minutes, and seconds. */
    t = t * 24 + tmP->tm_hour;
    t = t * 60 + tmP->tm_min;
    t = t * 60 + tmP->tm_sec;

    return t;
}

time_t c_httpd::tdate_parse (char* str) {

    struct tm tm;
    char* cp;
    char str_mon[500], str_wday[500];
    int tm_sec, tm_min, tm_hour, tm_mday, tm_year;
    long tm_mon, tm_wday;
    time_t t;

    /* Initialize. */
    (void) memset ( (char*) &tm, 0, sizeof (struct tm));

    /* Skip initial whitespace ourselves - sscanf is clumsy at this. */
    for (cp = str; *cp == ' ' || *cp == '\t'; ++cp)
        continue;

    /* And do the sscanfs.  WARNING: you can add more formats here,
    ** but be careful!  You can easily screw up the parsing of existing
    ** formats when you add new ones.  The order is important.
    */

    /* DD-mth-YY HH:MM:SS GMT */
    if (sscanf (cp, "%d-%400[a-zA-Z]-%d %d:%d:%d GMT",
                &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
                &tm_sec) == 6 &&
            scan_mon (str_mon, &tm_mon)) {
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
    }

    /* DD mth YY HH:MM:SS GMT */
    else if (sscanf (cp, "%d %400[a-zA-Z] %d %d:%d:%d GMT",
                     &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
                     &tm_sec) == 6 &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
    }

    /* HH:MM:SS GMT DD-mth-YY */
    else if (sscanf (cp, "%d:%d:%d GMT %d-%400[a-zA-Z]-%d",
                     &tm_hour, &tm_min, &tm_sec, &tm_mday, str_mon,
                     &tm_year) == 6 &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
    }

    /* HH:MM:SS GMT DD mth YY */
    else if (sscanf (cp, "%d:%d:%d GMT %d %400[a-zA-Z] %d",
                     &tm_hour, &tm_min, &tm_sec, &tm_mday, str_mon,
                     &tm_year) == 6 &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
    }

    /* wdy, DD-mth-YY HH:MM:SS GMT */
    else if (sscanf (cp, "%400[a-zA-Z], %d-%400[a-zA-Z]-%d %d:%d:%d GMT",
                     str_wday, &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
                     &tm_sec) == 7 &&
             scan_wday (str_wday, &tm_wday) &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_wday = tm_wday;
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
    }

    /* wdy, DD mth YY HH:MM:SS GMT */
    else if (sscanf (cp, "%400[a-zA-Z], %d %400[a-zA-Z] %d %d:%d:%d GMT",
                     str_wday, &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
                     &tm_sec) == 7 &&
             scan_wday (str_wday, &tm_wday) &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_wday = tm_wday;
        tm.tm_mday = tm_mday;
        tm.tm_mon = tm_mon;
        tm.tm_year = tm_year;
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
    }

    /* wdy mth DD HH:MM:SS GMT YY */
    else if (sscanf (cp, "%400[a-zA-Z] %400[a-zA-Z] %d %d:%d:%d GMT %d",
                     str_wday, str_mon, &tm_mday, &tm_hour, &tm_min, &tm_sec,
                     &tm_year) == 7 &&
             scan_wday (str_wday, &tm_wday) &&
             scan_mon (str_mon, &tm_mon)) {
        tm.tm_wday = tm_wday;
        tm.tm_mon = tm_mon;
        tm.tm_mday = tm_mday;
        tm.tm_hour = tm_hour;
        tm.tm_min = tm_min;
        tm.tm_sec = tm_sec;
        tm.tm_year = tm_year;
    } else {
        return (time_t) - 1;
    }

    if (tm.tm_year > 1900) {
        tm.tm_year -= 1900;
    } else if (tm.tm_year < 70) {
        tm.tm_year += 100;
    }

    t = tm_to_time (&tm);

    return t;
}

