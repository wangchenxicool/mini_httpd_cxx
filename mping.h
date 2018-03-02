#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>

#define DNS_PORT    53
#define DNS_IP      "202.96.134.133"
#define DNS_IP02    "8.8.8.8"
#define DNS_IP03    "114.114.114.114"
#define MAX_DOMAINNAME_LEN  255
#define LOOP -1

/* ICMP����ͷ�ṹ */
typedef struct Icmp {
    unsigned char type;         /* ���� */
    unsigned char code;         /* ���� */
    unsigned short check_sum;   /* ����� */
    unsigned short id;          /* ��ʶ�� */
    unsigned short seq;         /* ���к� */
} IcmpHeader;


/* IP���ݰ�ͷ�ṹ */
typedef struct _iphdr {

    unsigned int headLen: 4;        /* �ײ����� */
    unsigned int version: 4;        /* �汾 */
    unsigned char tos;              /* ���ַ��� */
    unsigned short totalLen;        /* �ܳ��� */
    unsigned short ident;           /* ��ʶ */
    unsigned short fragAndFlags;    /* ��־��Ƭƫ�� */
    unsigned char ttl;              /* ����ʱ�� */
    unsigned char proto;            /* Э�� */
    unsigned short checkSum;        /* ����� */
    unsigned int sourceIP;          /* Դ��ַ */
    unsigned int destIP;            /* Ŀ�ĵ�ַ */

} IpHeader;

typedef struct DNSheader {
    unsigned short id;
    unsigned char  qr_opcode_aa_tc_rd;  /* QR:0�����׼��ѯ��1�������ѯ��2���������״̬���� */
    unsigned char  ra_zero_rcode;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;

} DnsHeader;


typedef struct Ipaddr {
    unsigned short len;
    unsigned char a;
    unsigned char b;
    unsigned char c;
    unsigned char d;
} Ipadr;


/* ����ICMP����У���(����ǰҪ��) */
unsigned short get_checkSum (unsigned short *buf, int size);
/* ���ICMP������ľ������ */
void pack_icmp (char *icmp_data, int size);
/* �Է��ص�IP���ݰ����н�������λ��ICMP���� */
int parse_respone (char *buf, int bytes , const char *ip, int recv_time);
/* ��ʼ��ʱ */
int start_timer (struct timeval *stv);
/* ������ʱ */
int stop_timer (struct timeval *stv);
/* ִ��ping���� */
int ping (const char *ip,  int send_count);
