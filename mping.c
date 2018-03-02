#include "mping.h"
#include "safe.h"

/**
 * @brief    ����ICMP����У���(����ǰҪ��)
 *
 * @param   buf
 * @param   size
 *
 * @return  
 */
unsigned short get_checkSum (unsigned short *buf, int size)
{
    unsigned long sum = 0;
    int len = size / sizeof (unsigned short);

    /* �Ƚ�����16λ��� */
    while (len > 1) {
        sum += *buf++;
        len--;
    }

    /* �������ֽڣ�����������պ�16λ��תΪ16λ */
    if (size % sizeof (unsigned short)) {
        sum += * (unsigned char *) buf;
    } else {
        sum += *buf;
    }

    /* �ѽ�λȡ���������λ��� */
    while (sum > 0xffff) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /* ȡ���õ������ */
    return (unsigned short) (~sum);
}


/**
 * @brief    ���ICMP������ľ������
 *
 * @param   icmp_data
 * @param   size
 */
void pack_icmp (char *icmp_data, int size)
{
    bzero (icmp_data, 128);

    IcmpHeader *icmp_header = (IcmpHeader *) icmp_data;
    /* �������ݱ� ����Ϊ8 */
    icmp_header->type = 8;
    icmp_header->code = 0;
    icmp_header->id = (unsigned short) getpid();
    icmp_header->seq = 0;
    icmp_header->check_sum = 0;

    /* ���ICMP����������ݲ��� */
    char *data = icmp_data + sizeof (IcmpHeader);
    memset (data, 'x', size - sizeof (IcmpHeader));
    /* ���ü���� */
    icmp_header->check_sum = get_checkSum ( (unsigned short *) icmp_data, size);
}

/**
 * @brief    �Է��ص�IP���ݰ����н�������λ��ICMP����
 *
 * @param   buf
 * @param   bytes
 * @param   ip
 * @param   recv_time
 *
 * @return  
 */
int parse_respone (char *buf, int bytes , const char *ip, int recv_time)
{
    IpHeader *ip_header = (IpHeader *) buf;
    unsigned short ipHeadLen = ip_header->headLen * 4 ;

    if (bytes < ipHeadLen + 8 || ip_header->proto != 1) { /*  ICMP���ݲ�����, ���߲�����ICMP���� */
        return -1;
    }
    /* ժȥip���ݱ����ײ� */
    IcmpHeader *icmpHead = (IcmpHeader*) (buf + ipHeadLen);

    if (icmpHead->type != 0) {  /*  0��ʾ��Ӧ�� */
        if (icmpHead->type == 11) {
            printf ("time out!\n");
            return -1;
        }
        if (icmpHead->type == 3) {
            /* printf ("���� ����ip �Ļظ����޷�����Ŀ������\n"); */
            return -3;
        }
        return -2;
    }

    if (recv_time >= 0) {
        if (recv_time < 1) {
            /* printf ("���� %s �Ļظ��� �ֽ�=%d ʱ��<1ms TTL=%d \n", ip, bytes - ipHeadLen - sizeof (IcmpHeader), ip_header->ttl); */
            return 0;
        } else if (recv_time >= 1) {
            /* printf ("���� %s �Ļظ��� �ֽ�=%d ʱ��=%dms TTL=%d \n", ip, bytes - ipHeadLen - sizeof (IcmpHeader), recv_time, ip_header->ttl); */
        }
        return recv_time;
    }

    return 0;
}

/**
 * @brief    ��ʼ��ʱ
 *
 * @param   stv
 *
 * @return  
 */
int start_timer (struct timeval *stv)
{
    /* ��ÿ�ʼʱ�ĵ�ǰʱ�� */
    gettimeofday (stv, NULL);
    return 0;
}

/**
 * @brief    ������ʱ
 *
 * @param   stv
 *
 * @return  
 */
int stop_timer (struct timeval *stv)
{
    struct timeval etv;
    int time = 0;
    /* ��ý���ʱ�ĵ�ǰʱ�� */
    gettimeofday (&etv, NULL);
    if ( (etv.tv_usec -= stv->tv_usec) < 0) { /* ΢�� */
        --etv.tv_sec;
        etv.tv_usec += 1000000;
    }
    etv.tv_sec -= stv->tv_sec;  /* ���� */
    time = etv.tv_sec * 1000 + etv.tv_usec / 1000;
    return time;
}

/**
 * @brief    
 *
 * @param   rawfd
 * @param   dest_adr
 * @param   ip
 * @param   icmp_data
 * @param   all_time[]
 *
 * @return  
 */
int ping_one (int rawfd, struct sockaddr_in dest_adr, const char *ip, char *icmp_data, int all_time[])
{
    int return_ret = -1;
    char recv_buf[128];
    struct timeval stv;
    struct timeval etv;
    int recv_time = 0;
    struct sockaddr_in from_adr;
    socklen_t fromlen = 0;
    int size = sizeof (IcmpHeader) + 32;
    int r, i = 0, recv = 0, lost = 0;
    int TimeOuts = 0;
    /* ����icmp �������ݱ� */
    r = sendto (rawfd, icmp_data, size, 0, (struct sockaddr *) &dest_adr, sizeof (dest_adr));
    if (r < 0) {
        return -1;
    }
    /* ��ʼ��ʱ */
    start_timer (&stv);
    while (1) {
        /* ��ջ��� */
        bzero (recv_buf, sizeof (recv_buf));
        /* ����icmp ��Ӧ���ݱ� */
        fd_set rfds;
        FD_ZERO (&rfds);
        FD_SET (rawfd, &rfds);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int select_ret = 0;
        while ( (select_ret = select (rawfd + 1, &rfds, NULL, NULL, &tv)) == -1) {
            if (errno == EINTR) {
                fprintf (stderr, "A non blocked signal was caught\n");
                /* Necessary after an error */
                FD_ZERO (&rfds);
                FD_SET (rawfd, &rfds);
            } else {
                return_ret = -1;
                break;
            }
        }
        if (select_ret == 0) {
            /* Timeout */
            return_ret = -1;
            if (TimeOuts++ > 3) {
                break;
            } else {
                usleep (50);
            }
        } else {
            r = recvfrom (rawfd, recv_buf, 128, 0, (struct sockaddr *) &from_adr, &fromlen);
            if (r > 0) {
                /* ������ʱ */
                recv_time = stop_timer (&stv);
                /* ��ʼ��� */
                int ret = parse_respone (recv_buf, r, ip, recv_time);
                if (ret >= 0) { /* �����ȷ */
                    all_time[i] = recv_time;
                    return_ret = 0;
                } else if (ret == -2) { /* �յ������ */
                    i--;
                    continue;
                } else if (ret < -2) { /* δ֪���� */
                    break;
                    return -1;
                }
                break;
            } else if (r == -1) {
                return -1;
            }
        }
    }
    return return_ret;
}

/**
 * @brief    
 *
 * @param   ip
 * @param   send_count
 *
 * @return =1 �� ping ͨ, =others ���� ping ͨ  
 */
int ping (const char *ip,  int send_count)
{
    int rawfd;
    struct sockaddr_in dest_adr;
    char icmp_data[128];
    int size = sizeof (IcmpHeader) + 32;
    int i = 0;
    int all_time[128] = {0};

    for (i = 0; i < send_count; i++) {
        /* ����ԭʼ�׽��� */
        rawfd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (rawfd == -1) {
            perror ("create socket failed!");
        } else {
            /* ����Ŀ�ĵ�ַ��˿� */
            dest_adr.sin_family = AF_INET;
            dest_adr.sin_port = htons (80);
            inet_aton (ip, &dest_adr.sin_addr);
            /* ��װicmp���ݰ� */
            pack_icmp (icmp_data, size);
            if (ping_one (rawfd, dest_adr, ip, icmp_data , all_time) != -1) {
                close (rawfd);
                return 1;
            }
            close (rawfd);
        }
        wcx_sleep (0, 500*1000);
    }

    return -1;
}

/* ������ */
#if 0
int main (int argc, char const *argv[]) {
    /* ִ��ping */
    if (ping (argv[1], 1)) {
        printf ("online!\n");
    } else {
        printf ("offline!\n");
    }
    return 0;
}
#endif
