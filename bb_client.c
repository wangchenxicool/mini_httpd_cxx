#include "bb_client.h"

static int shmid;
static char *shm_addr;
static t_client_bb *p_clients;
static int shmid_cmd;
static char *shm_addr_cmd;

//pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t client_list_mutex;
t_cmd *p_cmd;


/**
 * @brief
 *
 * @return
 */
int clientlist_init (void) {

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&client_list_mutex, &attr);

    //XXX SHM
    if ( (shmid = shmget (IPC_PRIVATE, MAX_CLIENT_NUM * sizeof (t_client_bb), IPC_CREAT | 0666)) < 0) {
        perror ("shmget");
        return -1;
    } else {
        if ( (shm_addr = (char *) shmat (shmid, 0, 0)) == (void*) - 1) {
            perror ("Child:shmat");
            return -1;
        } else {
            memset (shm_addr, 0, MAX_CLIENT_NUM * sizeof (t_client_bb));
            p_clients = (t_client_bb *) shm_addr;
        }
    }
    //XXX SHM
    if ( (shmid_cmd = shmget (IPC_PRIVATE, sizeof (t_cmd), IPC_CREAT | 0666)) < 0) {
        perror ("shmget");
        return -1;
    } else {
        if ( (shm_addr_cmd = (char *) shmat (shmid_cmd, 0, 0)) == (void*) - 1) {
            perror ("Child:shmat");
            return -1;
        } else {
            memset (shm_addr_cmd, 0, sizeof (t_cmd));
            p_cmd = (t_cmd *) shm_addr_cmd;
        }
    }
    return 0;
}

/**
 * @brief
 *
 * @return
 */
int uninit_shm (void) {

    if (shmctl (shmid, IPC_RMID, NULL) == -1) {
        perror ("shmct:IPC_RMID");
        return -1;
    }
    if (shmctl (shmid_cmd, IPC_RMID, NULL) == -1) {
        perror ("shmct:IPC_RMID");
        return -1;
    }
    return 0;
}

t_client_bb *get_clients_ptr () {
    return p_clients;
}

int client_append (t_client_bb *ptr) {

    int i;
    t_client_bb *nt_ptr = p_clients;
    for (i = 0; i < MAX_CLIENT_NUM; i++) {
        if (0 == *(nt_ptr->ip)) {
            strlcpy (nt_ptr->ip, ptr->ip, sizeof (nt_ptr->ip));
            nt_ptr->authed = ptr->authed;
            nt_ptr->connect_time = ptr->connect_time;
            return 1;
        }
        nt_ptr++;
    }
    return 0;
}

void client_delete (t_client_bb * client) {

    int i;
    t_client_bb *ptr = p_clients;
    for (i = 0; i < MAX_CLIENT_NUM; i++) {
        if (!strcmp (ptr->ip, client->ip)) {
            * (ptr->ip) = 0;
        }
        ptr++;
    }
}

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client_bb *client_find_by_ip (const char *ip) {

    int i;
    t_client_bb *ptr = p_clients;

    for (i = 0; i < MAX_CLIENT_NUM; i++) {
        if (!strcmp (ptr->ip, ip)) {
            return ptr;
        }
        ptr++;
    }
    return NULL;
}

void client_delete_by_ip (const char * ip) {

    int i;
    t_client_bb *ptr = p_clients;
    for (i = 0; i < MAX_CLIENT_NUM; i++) {
        if (!strcmp (ip, ptr->ip)) {
            * (ptr->ip) = 0;
        }
        ptr++;
    }
}

/**
 * @brief 返回连接的mac设备的数量
 * @return
 */
int get_client_number () {

    int num = 0;
    t_client_bb *ptr = p_clients;
    for (int i = 0; i < MAX_CLIENT_NUM; i++) {
        if (*(ptr->ip) != 0) {
            num++;
        }
        ptr++;
    }
    return num;
}


t_client_bb * client_get_first (void) {

    t_client_bb *ptr = p_clients;
    return ptr;
}

