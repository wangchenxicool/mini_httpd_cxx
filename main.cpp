/**
 * @file main.cpp
 * @brief
 * @author wcx, wang_chen_xi_cool@qq.com
 * @version v0.1.0
 * @date 2017-11-01
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <linux/rtc.h>
#include <syslog.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "httpd.h"
#include "wcx_log.h"
#include "libiniparser/iniparser.h"
#include "bb_client.h"
#include "my_popen.h"
#include "safe.h"
#include "mping.h"
#include "safe.h"
#include "md5.h"
#include "config.h"
#include "terminal_color.h"
#include "./json_njsk/json.h"


#define CGI_WEB_CMD                 "web_cmd"

static const char *gversion     = "web_for_xuhui_8.0.0";
static int         do_fork      = 1;
static bool        g_exit_flag  = false;
static char        g_www_root[128];

string& replace_all (string& str, const string& old_value, const string& new_value)
{
    while (true) {
        int pos = 0;
        if ( (pos = str.find (old_value, 0)) != string::npos)
            str.replace (pos, old_value.length(), new_value);
        else break;
    }
    return str;
}
string& repalce_all_ditinct (string& str, const string&old_value, const string& new_value)
{
    for (string::size_type pos (0); pos != string::npos; pos += new_value.length()) {
        if ( (pos = str.find (old_value, pos)) != string::npos)
            str.replace (pos, old_value.length(), new_value);
        else break;
    }
    return str;
}
string& repalce_all_my (string& str, const string&old_value, const string& new_value)
{
    for (int pos = 0; pos != -1; pos += new_value.length())
        if ( (pos = str.find (old_value, pos)) != -1)
            str.replace (pos, old_value.length(), new_value);
        else break;
    return str;
}


/**
 * @brief    检测 mac 设备是否认证过
 *
 * @param   ip
 *
 * @return  =true 已认证, =false 未认证
 */
bool is_authed (const char *ip)
{
    t_client_bb *pclient;
    if ( (pclient = client_find_by_ip (ip)) == NULL) {
        return false;
    }
    if (!pclient->authed) {
        return false;
    }
    return true;
}

/**
 * @brief create_file
 * @param file_name
 * @return
 */
int create_file (const char *cgi_dir, const char *file_name)
{
    char cgi_file[256];
    memset (cgi_file, 0, sizeof (cgi_file));
    snprintf (cgi_file, sizeof (cgi_file), "%s/%s", cgi_dir, file_name);
    if (access (cgi_file, 0) == -1) {
        FILE *fp = fopen (cgi_file, "w");
        if (fp != NULL) {
            fclose (fp);
        }
    }
}

int create_dirs_files (const char *www_root)
{
    // www_root
    if (access (www_root, 0) == -1) {
        DEBUG_LOG ("'%s' not existing, make it!", www_root);
        int flag = mkdir (www_root, 0777);
        if (flag == 0) {
            DEBUG_LOG ("make '%s' successfully!", www_root);
        } else {
            WARNING_LOG ("mkdir '%s' failed:%s", www_root, strerror (errno));
        }
    }
    // CGI_DIR
    char cgi_dir[128];
    snprintf (cgi_dir, sizeof (cgi_dir), "%s/cgi-bin", www_root);
    if (access (cgi_dir, 0) == -1) {
        DEBUG_LOG ("'%s' not existing, make it!", cgi_dir);
        int flag = mkdir (cgi_dir, 0777);
        if (flag == 0) {
            DEBUG_LOG ("make '%s' successfully!", cgi_dir);
        } else {
            WARNING_LOG ("make '%s' failed! %s", cgi_dir, strerror (errno));
        }
    }
    // create conf file
    char conf_file[128];
    snprintf (conf_file, sizeof (conf_file), "%s/httpd.conf", www_root);
    if (access (conf_file, 0) == -1) {
        FILE *fp;
        fp = fopen (conf_file, "w");
        if (fp != NULL) {
            char str[512];
            memset (str, 0, sizeof (str));
            snprintf (str, sizeof (str),
                      "port=9527\n"
                      "dir=%s\n"
                      "cgipat=%s\n"
                      "user=nobody\n"
                      "pidfile=%s/httpd.pid\n"
                      "logfile=%s/httpd.log\n",
                      www_root,
                      "cgi-bin/*",
                      www_root,
                      www_root);
            fwrite (str, strlen (str), 1, fp);
            fclose (fp);
        }
    }

    // create_file
    create_file (cgi_dir, CGI_WEB_CMD);

    DEBUG_LOG ("create_fils_dirs end!");
    return 0;
}

/**
 * @brief    out text to http client
 *
 * @param   fd
 * @param   code
 * @param   text
 */
void out_text (int fd, int code, const char *text)
{
    char *response = NULL;
    int size_len = strlen (text) + 256;
    response = (char*) malloc (size_len);
    if (response == NULL) {
        return;
    }
    memset (response, 0, size_len);
    snprintf (response, size_len,
              "HTTP/1.0 200 OK\n"
              "Connection: close\n"
              "Access-Control-Allow-Origin:*\n"
              "Content-type: application/json\r\n\r\n"
              "{\"code\":\"%d\",\"data\":{},\"details\":\"%s\"}\r\n\r\n",
              code, text);
    write (fd, response, strlen (response));
    DEBUG_LOG ("code:%d,response:%s", code, text);
    if (response) {
        free (response);
    }
}

void out_token (int fd, const char *mac, time_t *date)
{
    char response[512];
    memset (response, 0, sizeof (response));
    snprintf (response, sizeof (response),
              "HTTP/1.0 200 OK\n"
              "Connection: close\n"
              "Access-Control-Allow-Origin:*\n"
              "Content-type: application/json\r\n\r\n"
              "{\"code\":\"0\",\"data\":{\"mac\":\"%s\", \"time\":\"%ld\"},\"details\":\"ok\"}\r\n\r\n",
              mac, *date);

    write (fd, response, strlen (response));
}

/**
 * @brief
 *
 * @param   cmd
 * @param   response
 * @param   ErrNo
 *
 * @return
 */
int safe_system_malloc (const char *cmd, char **response, int *ErrNo)
{
    FILE *pp;
    char buff[1024];
    *response = NULL;
    int tmpres = 0;
    int recvnum = 0;

    pp = popen (cmd, "r");
    if (!pp) {
        *ErrNo = errno;
        return -1;
    }
    while (!feof (pp)) {
        memset (buff, 0, sizeof (buff));
        tmpres = fread (buff, sizeof (char), sizeof (buff), pp);
        if (tmpres <= 0) {
            continue;
        }

        /* Sums bytes received */
        recvnum += tmpres;

        if (*response == NULL) {
            *response = (char*) malloc (recvnum);
            if (*response == NULL) {
                *ErrNo = errno;
                return -1;
            }
        } else {
            *response = (char*) realloc (*response, recvnum);
            if (*response == NULL) {
                *ErrNo = errno;
                return -1;
            }
        }
        memcpy (*response + recvnum - tmpres, buff, tmpres);
    }
    printf ("safe_system_malloc::fread:{%s},recvnum:%d\n", *response, recvnum);

    pclose (pp);
    return recvnum;
}

/**
 * @brief    httpd 回调函数, 处理业务逻辑, 调用执行后继续这些httpd
 *
 * @param   ip: ip地址, 注意: 不能修改其中的数据
 * @param   mac: mac地址, 注意: 不能修改其中的数据
 * @param   rcv_data: 收到的httpclient的原始数据, 注意: 不能修改其中的数据
 *
 * @return: 如果是帮帮apk的请求帧返回1, 除此之外的所有不认识的帧, 返回0(包括cgi)
 */
int httpd_rcv_cb (const char* ip, const char *mac, char *rcv_data)
{
#if 0
    printf ("-------------- start httpd_rcv_cb -----------\n");
    printf ("ip: %s\n", ip);
    printf ("mac: %s\n", mac);
    printf ("rcv_data: %s\n", rcv_data);
    printf ("-------------- end httpd_rcv_cb -------------\n");
#endif

#if 0
    //test bb_write
    httpd->bb_write ("This is Test bb_write", strlen ("This is Test bb_write"));
#endif

#if 0
    //test httpdOutMsg
    httpd->httpdOutMsg (1, "This is Test bb_write");
#endif

#if 0
    //test httpdOutToken
    httpd->httpdOutToken ("mac", "date");
#endif

    if (0) {
        //处理帮帮业务
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief   cgi 回调函数
 *
 * @param   binary: cgi 命令名称, 注意: 不能修改之
 * @param   argp : cig 参数组, 注意: 不能修改之
 *
 * @return : 如果是帮帮的业务, 处理完后返回1, 否则, 返回0, httpd将继续执行cgi命令
 */
int httpd_cgi_cb (int fd,
                  const char *ip, const char *mac,
                  const char *binary, const char **argp,
                  char *rcv_data)
{
    printf ("@@@@@@@@@@@@@@@@@ start httpd_cgi_cb @@@@@@@@@@@@@@@@@\n");
    printf ("ip: %s\n", ip);
    printf ("binary: %s\n", binary);
    int par_num = 0;
    while (1) {
        if (argp[par_num] != (char *) 0) {
            printf ("argp-%d: %s\n", par_num, argp[par_num]);
        } else {
            break;
        }
        par_num++;
    }
    printf ("################## end httpd_cgi_cb ##################\n");
    printf ("par_num:%d\n", par_num);

    int     ret = -1;
    int     ErrNo = 0;
    char    cmd[512];

    /**
     * @brief CGI_WEB_CMD
     * http://10.8.10.219:9527/cgi-bin/web_cmd?dir
     */
    if (0 == strncasecmp (binary, CGI_WEB_CMD, strlen (CGI_WEB_CMD))) {
        if (par_num != 2) {
            out_text (fd, -1, "par_num failed!");
            return 1;
        }
        char *presponse = NULL;
        ret = safe_system_malloc (argp[1], &presponse, &ErrNo);
        if (ret == -1) {
            out_text (fd, -1, strerror (ErrNo));
        } else if (ret == 0) {
            out_text (fd, 0, "ok");
        } else {
            out_text (fd, 0, presponse);
        }
        if (presponse) {
            free (presponse);
        }
        return 1;
    }

    return 0;
}

/**
 * @brief work_init
 * @return
 */
bool work_init () 
{
    syslog (LOG_DEBUG, "work_init..");
    DEBUG_LOG ("work_init..");
    return true;
}

static void work_loop (const char * data) 
{
    syslog (LOG_DEBUG, "work_loop start(%d)", getpid());
    DEBUG_LOG ("work_loop()", "start..");

    /**
     * @brief 处理cgi回调
     */
    int r = fork();
    if (r < 0) {
        syslog (LOG_CRIT, "fork - %m");
        ERROR_LOG ("fork for network_manager failed! %s", strerror (errno));
        exit (1);
    }
    if (r == 0) {
        /* Child process. */
        syslog (LOG_DEBUG, "start httpd..");
        c_httpd *httpd = new c_httpd (data);
        httpd->set_debug ();
        httpd->set_port (9527);
        httpd->set_rcv_call_back (httpd_rcv_cb);
        httpd->set_do_cgi_call_back (httpd_cgi_cb);
        httpd->run ();
        exit (0);
    }

    // 初始化工作
    if (work_init ()) {
        syslog (LOG_DEBUG, "work_init sucess!");
        DEBUG_LOG ("work_init sucess!");
    } else {
        syslog (LOG_DEBUG, "work_init failed!");
        DEBUG_LOG ("work_init failed!");
        raise (SIGTERM);
    }

    while (!g_exit_flag) {
       sleep (2);
    }
    
    syslog (LOG_DEBUG, "work_loop is closed.");
    DEBUG_LOG ("work_loop()", "end");
}

/**
 * @brief   信号处理函数
 *
 * @param   signum
 */
void signup (int signum)
{
    switch (signum) {

    case SIGUSR1:
        break;

    case SIGUSR2:
        break;

    case SIGPIPE:
        syslog (LOG_DEBUG, "Broken PIPE");
        WARNING_LOG ("Broken PIPE");

    case SIGHUP:
        WARNING_LOG ("SIGHUP");

    case SIGTERM:
        WARNING_LOG ("SIGTERM");
        g_exit_flag = true;
        sleep (1);
        exit (1);

    case SIGABRT:
        WARNING_LOG ("SIGABRT");

    case SIGINT: {
        WARNING_LOG ("SIGINT");
        g_exit_flag = true;
        sleep (1);
        exit (1);
    }
        break;

    case SIGCHLD: {
        //        WARNING_LOG ("SIGCHLD");
        wait ( (int*) 0);
    }
        break;

    default:
        syslog (LOG_DEBUG, "Do nothing, %d", signum);
        WARNING_LOG ("Do nothing, %d", signum);
        break;
    }
}

/**
 * @brief    重新绑定信号处理函数
 */
void init_signals (void)
{
    //    signal (SIGTERM, signup);
    //    signal (SIGABRT, signup);
    //    signal (SIGUSR1, signup);
    //    signal (SIGUSR2, signup);
    //    signal (SIGPIPE, signup);
    //    signal (SIGINT, signup);
}

/**
 * @brief print_usage
 * @param prog
 */
void print_usage (const char * prog)
{
    my_system ("clear");
    printf ("Usage: %s [-d]\n", prog);
    puts ("  -d  --set debug mode\n");
}

int parse_opts (int argc, char * argv[])
{
    int ch;

    do_fork = 1;
    getcwd (g_www_root, sizeof (g_www_root));

    while ( (ch = getopt (argc, argv, "dD:")) != EOF) {
        switch (ch) {
            case 'd':
                printf ("debug mode..\n");
                do_fork = 0;
                break;
            case 'D':
                snprintf (g_www_root, sizeof (g_www_root), "%s", optarg);
                break;
            case 'h':
            case '?':
                print_usage (argv[0]);
                return -1;
            default:
                break;
        }
    }

    //去掉 www_root 最后面的'\'
    char *p = g_www_root + strlen (g_www_root) - 1;
    if (*p == '/') {
        *p = '\0';
    }
    printf ("wwwroot:%s\n", g_www_root);

    return 0;
}


int main (int argc, char * argv[]) 
{
    /**
     * @brief parse opts
     */
    syslog (LOG_DEBUG, "parse opts..");
    int ret = parse_opts (argc, argv);
    if (ret < 0) {
        exit (0);
    }

    /**
     * @brief 创建web根目录
     */
    syslog (LOG_DEBUG, "create web dir..");
    if (access (g_www_root, 0) == -1) {
        int ret = mkdir (g_www_root, 0777);
        if (ret == 0) {
            printf ("make '%s' successfully!", g_www_root);
        } else {
            printf ("mkdir:%s", strerror (errno));
        }
    }

    /**
     * @brief openlog
     */
    openlog ("httpd", LOG_NDELAY | LOG_PID, LOG_DAEMON);
    syslog (LOG_DEBUG, "######## httpd start... ########");
    char log_file[50];
    snprintf(log_file, sizeof(log_file), "%s/httpd", g_www_root);
    INIT_LOG (log_file, "httpd", gversion);

    /**
     * @brief 读配置文件
     */
    syslog (LOG_DEBUG, "read ini file..");
    if (!g_config.load ()) {
        ERROR_LOG ("read ini file failed!");
//        exit (1);
    }

    /**
     * @brief clientlist_init
     */
    syslog (LOG_DEBUG, "clientlist_init ..\n");
    if (clientlist_init () == 0) {
        printf ("clientlist_init sucess!\n");
    } else {
        printf ("clientlist_init failed!\n");
    }

    /**
     * @brief create_dirs_files
     */
    create_dirs_files (g_www_root);

    /**
     * @brief init_signals
     */
    init_signals ();

    /**
     * @brief  background ourself Make ourselves a daemon.
     */
    if (do_fork) {
        syslog (LOG_DEBUG, "do_fork..");
        printf ("daemon..\n");
        if (daemon (1, 1) < 0) {
            syslog (LOG_CRIT, "daemon - %m");
            perror ("daemon");
            exit (1);
        }
    } else {
        /* Even if we don't daemonize, we still want to disown our parent
         * process. */
        (void) setsid();
    }

    /**
     * @brief While loop util program finish
     */
    syslog (LOG_DEBUG, "work_loop...");
    char conf_file[128];
    snprintf (conf_file, sizeof (conf_file), "%s/httpd.conf", g_www_root);
    work_loop (conf_file);

    /**
     * @brief exit
     */
    printf ("mini_httpd is finished!\n");
    exit (0);

}
