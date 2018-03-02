#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "wcx_log.h"
#include "safe.h"
#include "libiniparser/iniparser.h"

#define BBDOG_CONF_FILE     "/etc/httpd.conf"
#define GW_INTERFACE        "br-lan"

typedef struct {
    char ProuctType;            //产品类型
    char isKick;                //是否“踢人”
    char isShowHome;            //是否弹首页
    char ApClientMax;           //Ap能接入的最多用户数，超过的立即“踢走”
    char LocalMac[30];          //MTK自己的Ap的mac地址
    char ApKeyType[20];         //Ap热点加密方式
    char ApKey[64];             //Ap密码
    char isUpdateLogOntime;     //是否定时上传日志
    char MTKID[20];             //自己的ID号，从服务器获取
    char BangZoneAddr[50];      //帮帮服务器地址
    int BangZonePort;           //帮帮服务器端口
    char ApDriverType;          //Ap驱动类型，1：mac80211 2：rt2860v2
    char isApClientMode;        //是否为ApClient模式
    char isHave3GMode;          //是否有3G模块
    char ethStaticDns[40];      //有线静态上网时的dns: 218.218.219.219 222.222.222.222
    char isTestMode;            //是否是测试模式
} config_t;

class Config {

public:
    Config ();
    ~Config ();

private:
    int shmid;
    char *shm_addr;
    config_t *p_config;

private:
    void init ();
    void uninit ();

public:
    bool load (void);
    bool ConfigSetKey (const char *file, const char *entry, const char *key, const char *value);

public:
    char* getLocalMac ();
    char* getLocalShortMac ();
    int getProuctType ();
    void setProuctType (int type);
    bool getIsKick ();
    void setIsKick (bool val);
    bool getIsShowHome ();
    void setIsShowHome (bool val);
    int getApClientMax ();
    void setApClientMax (int val);
    const char* getApKeyType ();
    void setApKeyType (const char *type);
    const char* getApKey ();
    void setApKey (const char *key);
    bool getIsUpdateLogOntime ();
    void setIsUpdateLogOntime (bool val);
    const char* getMTKID ();
    void setMTKID (const char *id);
    const char* getBangZoneAddr ();
    void setBangZoneAddr (const char *addr);
    int getBangZonePort ();
    void setBangZonePort (int port);
    bool getIsApClientMode ();
    void setIsApClientMode (bool val);
    int getApDriverType ();
    void setApDriverType (int type);
    bool getIsHave3GMode ();
    void setIsHave3GMode (bool val);
    const char* getEthStaticDns ();
    void setEthStaticDns (const char *addr);
    bool getIsTestMode ();
    void setIsTestMode (bool val);

};

extern Config g_config;

#endif
