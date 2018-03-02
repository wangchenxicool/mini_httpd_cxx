#include "mping.h"
#include "safe.h"

/**
 * @brief    计算ICMP包的校验和(发送前要用)
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

    /* 先将所有16位相加 */
    while (len > 1) {
        sum += *buf++;
        len--;
    }

    /* 加最后的字节，如果不是两刚好16位则转为16位 */
    if (size % sizeof (unsigned short)) {
        sum += * (unsigned char *) buf;
    } else {
        sum += *buf;
    }

    /* 把进位取出来再与低位相加 */
    while (sum > 0xffff) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /* 取反得到检验和 */
    return (unsigned short) (~sum);
}


/**
 * @brief    填充ICMP请求包的具体参数
 *
 * @param   icmp_data
 * @param   size
 */
void pack_icmp (char *icmp_data, int size)
{
    bzero (icmp_data, 128);

    IcmpHeader *icmp_header = (IcmpHeader *) icmp_data;
    /* 请求数据报 类型为8 */
    icmp_header->type = 8;
    icmp_header->code = 0;
    icmp_header->id = (unsigned short) getpid();
    icmp_header->seq = 0;
    icmp_header->check_sum = 0;

    /* 填充ICMP请求包的数据部分 */
    char *data = icmp_data + sizeof (IcmpHeader);
    memset (data, 'x', size - sizeof (IcmpHeader));
    /* 设置检验和 */
    icmp_header->check_sum = get_checkSum ( (unsigned short *) icmp_data, size);
}

/**
 * @brief    对返回的IP数据包进行解析，定位到ICMP数据
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

    if (bytes < ipHeadLen + 8 || ip_header->proto != 1) { /*  ICMP数据不完整, 或者不包含ICMP数据 */
        return -1;
    }
    /* 摘去ip数据报的首部 */
    IcmpHeader *icmpHead = (IcmpHeader*) (buf + ipHeadLen);

    if (icmpHead->type != 0) {  /*  0表示回应包 */
        if (icmpHead->type == 11) {
            printf ("time out!\n");
            return -1;
        }
        if (icmpHead->type == 3) {
            /* printf ("来自 本地ip 的回复：无法访问目标主机\n"); */
            return -3;
        }
        return -2;
    }

    if (recv_time >= 0) {
        if (recv_time < 1) {
            /* printf ("来自 %s 的回复： 字节=%d 时间<1ms TTL=%d \n", ip, bytes - ipHeadLen - sizeof (IcmpHeader), ip_header->ttl); */
            return 0;
        } else if (recv_time >= 1) {
            /* printf ("来自 %s 的回复： 字节=%d 时间=%dms TTL=%d \n", ip, bytes - ipHeadLen - sizeof (IcmpHeader), recv_time, ip_header->ttl); */
        }
        return recv_time;
    }

    return 0;
}

/**
 * @brief    开始计时
 *
 * @param   stv
 *
 * @return  
 */
int start_timer (struct timeval *stv)
{
    /* 获得开始时的当前时间 */
    gettimeofday (stv, NULL);
    return 0;
}

/**
 * @brief    结束计时
 *
 * @param   stv
 *
 * @return  
 */
int stop_timer (struct timeval *stv)
{
    struct timeval etv;
    int time = 0;
    /* 获得结束时的当前时间 */
    gettimeofday (&etv, NULL);
    if ( (etv.tv_usec -= stv->tv_usec) < 0) { /* 微秒 */
        --etv.tv_sec;
        etv.tv_usec += 1000000;
    }
    etv.tv_sec -= stv->tv_sec;  /* 毫秒 */
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
    /* 发送icmp 请求数据报 */
    r = sendto (rawfd, icmp_data, size, 0, (struct sockaddr *) &dest_adr, sizeof (dest_adr));
    if (r < 0) {
        return -1;
    }
    /* 开始计时 */
    start_timer (&stv);
    while (1) {
        /* 清空缓存 */
        bzero (recv_buf, sizeof (recv_buf));
        /* 发送icmp 回应数据报 */
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
                /* 结束计时 */
                recv_time = stop_timer (&stv);
                /* 开始解包 */
                int ret = parse_respone (recv_buf, r, ip, recv_time);
                if (ret >= 0) { /* 解包正确 */
                    all_time[i] = recv_time;
                    return_ret = 0;
                } else if (ret == -2) { /* 收到错误包 */
                    i--;
                    continue;
                } else if (ret < -2) { /* 未知错误 */
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
 * @return =1 能 ping 通, =others 不能 ping 通  
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
        /* 创建原始套接字 */
        rawfd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (rawfd == -1) {
            perror ("create socket failed!");
        } else {
            /* 设置目的地址与端口 */
            dest_adr.sin_family = AF_INET;
            dest_adr.sin_port = htons (80);
            inet_aton (ip, &dest_adr.sin_addr);
            /* 封装icmp数据包 */
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

/* 主函数 */
#if 0
int main (int argc, char const *argv[]) {
    /* 执行ping */
    if (ping (argv[1], 1)) {
        printf ("online!\n");
    } else {
        printf ("offline!\n");
    }
    return 0;
}
#endif
