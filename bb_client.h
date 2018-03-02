#ifndef BB_CLIENT_H
#define BB_CLIENT_H

#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/timeb.h>
#include "safe.h"

#define MAX_CLIENT_NUM  50

#define LOCK_CLIENT_LIST() do { \
    pthread_mutex_lock(&client_list_mutex); \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
	pthread_mutex_unlock(&client_list_mutex); \
} while (0)

typedef struct	_t_client_bb {

    char ip[INET_ADDRSTRLEN];	/**< @brief Client Ip address */
    //char mac[20];	    		[>*< @brief Client Mac address <]
    char token[35];	    		/**< @brief Client token */

    bool authed;                /**< @brief Client 是否认证标志 */
    time_t  connect_time;       /* 连接时的时间戳 */

} t_client_bb;

typedef struct {

    int cmd;
    char arg1[50];
    char arg2[50];
    char arg3[50];
    char arg4[50];
    char arg5[50];
    char arg6[50];
    int status;
    int result;
    char msg[128];
    //XXX
    char watdog_mode;

} t_cmd;

int clientlist_init (void);
int uninit_shm (void);
int client_append (t_client_bb * ptr);
void client_delete (t_client_bb * client);
t_client_bb * client_find_by_ip (const char *ip);
void client_delete_by_ip (const char * ip);
t_client_bb * client_get_first (void);
t_client_bb *get_clients_ptr ();
int get_client_number ();

extern pthread_mutex_t client_list_mutex;
extern t_cmd *p_cmd;

#endif
