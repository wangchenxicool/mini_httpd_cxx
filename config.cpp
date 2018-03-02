#include <sys/shm.h>
#include "config.h"
#include "wcx_log.h"
#include "terminal_color.h"

Config::Config () {
    init ();
}

Config::~Config () {
    uninit ();
}

/**
 * @brief Config::init
 */
void Config::init ()
{
    shmid = 0;
    shm_addr = 0;
    p_config = 0;

    if ( (shmid = shmget (IPC_PRIVATE, sizeof (config_t), IPC_CREAT | 0666)) < 0) {
        syslog (LOG_DEBUG, RED"%-15s""shget failed: %s"GRAY, "config:", strerror(errno));
        ERROR_LOG ("shget failed:%s", strerror(errno));
        exit (1);
    } else {
        if ( (shm_addr = (char *) shmat (shmid, 0, 0)) == (void*) - 1) {
            syslog (LOG_DEBUG, RED"%-15s""shmt failed: %s"GRAY, "config:", strerror(errno));
            ERROR_LOG ("shmt failed:%s", strerror(errno));
            exit (1);
        } else {
            memset (shm_addr, 0, sizeof (config_t));
            p_config = (config_t*) shm_addr;
        }
    }
    p_config->isTestMode = 0;

    FILE *fp = fopen (BBDOG_CONF_FILE, "r");
    if (fp) {
        fclose (fp);
        return;
    }

    /**
     * @brief 设置默认值
     */
    p_config->isApClientMode = 0;
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ProuctType", "1");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isKick", "1");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isShowHome", "0");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApClientMax", "20");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApKeyType", "psk2");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApKey", "12345678");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isUpdateLogOntime", "0");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "MTKID", "none");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "BangZoneAddr", "www.bangzone.cn");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "BangZonePort", "80");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApDriverType", "1");
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ethStaticDns", "8.8.8.8");
}

void Config::uninit ()
{
    if (shmctl (shmid, IPC_RMID, NULL) == -1) {
        perror ("shmct:IPC_RMID");
    }
}

bool Config::ConfigSetKey (const char *file, const char *entry, const char *key, const char *value) {

    FILE *fp;
    dictionary  *ini;
    ini = iniparser_load (file);
    if (ini == NULL) {
        fp = fopen (file, "w");
        if (!fp) {
            perror ("fopen");
            return false;
        }
        fclose (fp);
        ini = iniparser_load (file);
        if (ini == NULL) {
            printf ("iniparser_load failed!\n");
            return false;
        }
    }

    int ret = iniparser_set (ini, entry, NULL);
    if (ret == -1) {
        iniparser_freedict (ini);
        printf ("iniparser_set NULL failed!\n");
        return false;
    }
    char buf[128];
    memset (buf, 0, sizeof (buf));
    snprintf (buf, sizeof (buf), "%s:%s", entry, key);
    ret += iniparser_set (ini, buf, value);
    if (ret == -1) {
        iniparser_freedict (ini);
        printf ("iniparser_set val failed!\n");
        return false;
    }

    fp = fopen (file, "w");
    if (!fp) {
        perror ("fopen");
        iniparser_freedict (ini);
        return false;
    }
    iniparser_dump_ini (ini, fp);
    fflush (fp);
    fclose (fp);

    iniparser_freedict (ini);
    return true;
}

/**
 * @brief Config::load
 * @return
 */
bool Config::load (void)
{
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return false;
    }

    //XXX 产品类型
    p_config->ProuctType = iniparser_getint (ini, "httpd:ProuctType", 1);
    syslog(LOG_DEBUG, GREEN"%-15s""ProuctType:%d"GRAY, "config:", p_config->ProuctType);
    DEBUG_LOG("ProuctType:%d", p_config->ProuctType);

    //XXX 是否“踢人”
    p_config->isKick = iniparser_getint (ini, "httpd:isKick", 1);
    syslog(LOG_DEBUG, GREEN"%-15s""isKick:%d"GRAY, "config:", p_config->isKick);
    DEBUG_LOG("isKick:%d", p_config->isKick);

    //XXX 是否弹首页
    p_config->isShowHome = iniparser_getint (ini, "httpd:isShowHome", 0);
    syslog(LOG_DEBUG, GREEN"%-15s""isShowHome:%d"GRAY, "config:", p_config->isShowHome);
    DEBUG_LOG("isShowHome:%d", p_config->isShowHome);

    //XXX Ap能接入的最多用户数，超过的立即“踢走”
    p_config->ApClientMax = iniparser_getint (ini, "httpd:ApClientMax", 20);
    syslog(LOG_DEBUG, GREEN"%-15s""ApClientMax:%d"GRAY, "config:", p_config->ApClientMax);
    DEBUG_LOG("ApClientMax:%d", p_config->ApClientMax);

    //XXX Ap热点加密方式
    strlcpy(p_config->ApKeyType, iniparser_getstring (ini, "httpd:ApKeyType", "psk2"), sizeof (p_config->ApKeyType));
    syslog(LOG_DEBUG, GREEN"%-15s""ApKeyType:%s"GRAY, "config:", p_config->ApKeyType);
    DEBUG_LOG("ApKeyType:%s", p_config->ApKeyType);

    //XXX Ap密码
    strlcpy(p_config->ApKey, iniparser_getstring (ini, "httpd:ApKey", "12345678"), sizeof (p_config->ApKey));
    syslog(LOG_DEBUG, GREEN"%-15s""ApKey:%s"GRAY, "config:", p_config->ApKey);
    DEBUG_LOG("ApKey:%s", p_config->ApKey);

    //XXX 是否定时上传日志
    p_config->isUpdateLogOntime = iniparser_getint (ini, "httpd:isUpdateLogOntime", 0);
    syslog(LOG_DEBUG, GREEN"%-15s""isUpdateLogOntime:%d"GRAY, "config:", p_config->isUpdateLogOntime);
    DEBUG_LOG("isUpdateLogOntime:%d", p_config->isUpdateLogOntime);

    //XXX MTKID
    strlcpy(p_config->MTKID, iniparser_getstring (ini, "httpd:MTKID", "none"), sizeof (p_config->MTKID));
    syslog(LOG_DEBUG, GREEN"%-15s""MTKID:%s"GRAY, "config:", p_config->MTKID);
    DEBUG_LOG("MTKID:%s", p_config->MTKID);

    //XXX BangZoneAddr
    strlcpy(p_config->BangZoneAddr, iniparser_getstring (ini, "httpd:BangZoneAddr", "www.bangzone.cn"),
            sizeof (p_config->BangZoneAddr));
    syslog(LOG_DEBUG, GREEN"%-15s""BangZoneAddr:%s"GRAY, "config:", p_config->BangZoneAddr);
    DEBUG_LOG("BangZoneAddr:%s", p_config->BangZoneAddr);

    //XXX BangZonePort
    p_config->BangZonePort = iniparser_getint (ini, "httpd:BangZonePort", 80);
    syslog(LOG_DEBUG, GREEN"%-15s""BangZonePort:%d"GRAY, "config:", p_config->BangZonePort);
    DEBUG_LOG("BangZonePort:%d", p_config->BangZonePort);

    //XXX 是否为ApClient模式
    char wwan_proto[50];
    strncpy (wwan_proto, "none", sizeof (wwan_proto));
    FILE *pp = popen ("uci get network.wwan.proto", "r");
    if (pp) {
        fscanf (pp, "%s", wwan_proto);
        pclose (pp);
    }
    if (strstr(wwan_proto, "dhcp")) {
        p_config->isApClientMode = 1;
    } else {
        p_config->isApClientMode = 0;
    }
    syslog(LOG_DEBUG, GREEN"%-15s""isApClientMode:%d"GRAY, "config:", p_config->isApClientMode);
    DEBUG_LOG("isApClientMode:%d", p_config->isApClientMode);

    //XXX 检查是否有3G模块
    char dev_3g[50];
    strncpy (dev_3g, "none", sizeof (dev_3g));
    pp = popen ("ls /dev/ttyUSB0", "r");
    if (pp) {
        fscanf (pp, "%s", dev_3g);
        pclose (pp);
    }
    if (strstr(dev_3g, "ttyUSB0")) {
        p_config->isHave3GMode = 1;
    } else {
        p_config->isHave3GMode = 0;
    }
    syslog(LOG_DEBUG, GREEN"%-15s""isHave3GMode:%d"GRAY, "config:", p_config->isHave3GMode);
    DEBUG_LOG("isHave3GMode:%d", p_config->isHave3GMode);

    //XXX 有线静态上网时的dns
    strlcpy(p_config->ethStaticDns, iniparser_getstring (ini, "httpd:ethStaticDns", "8.8.8.8"), sizeof (p_config->ethStaticDns));
    syslog(LOG_DEBUG, GREEN"%-15s""ethStaticDns:%s"GRAY, "config:", p_config->ethStaticDns);
    DEBUG_LOG("ethStaticDns:%s", p_config->ethStaticDns);

    iniparser_freedict (ini);
    return true;
}

char* Config::getLocalMac () {
    return p_config->LocalMac;
}
char* Config::getLocalShortMac () {
    return &(p_config->LocalMac[4]);
}
//
int Config::getProuctType () {
    return p_config->ProuctType;
}
void Config::setProuctType (int type) {
    p_config->ProuctType = type;
    char value[128];
    snprintf(value, sizeof(value), "%d", type);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ProuctType", value);
}
//
int Config::getApDriverType () {
    return p_config->ApDriverType;
}
void Config::setApDriverType (int type) {
    p_config->ApDriverType = type;
    char value[128];
    snprintf(value, sizeof(value), "%d", type);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApDriverType", value);
}
//
bool Config::getIsKick () {
    if (p_config->isKick == 1) {
        return true;
    }
    return false;
}
void Config::setIsKick (bool val) {
    if (val) {
        p_config->isKick = 1;
    } else {
        p_config->isKick = 0;
    }
    char value[128];
    snprintf(value, sizeof(value), "%d", p_config->isKick);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isKick", value);
}
//
bool Config::getIsHave3GMode () {
    if (p_config->isHave3GMode == 1) {
        return true;
    }
    return false;
}
void Config::setIsHave3GMode (bool val) {
    if (val) {
        p_config->isHave3GMode = 1;
    } else {
        p_config->isHave3GMode = 0;
    }
}
//
bool Config::getIsApClientMode () {
    if (p_config->isApClientMode == 1) {
        return true;
    }
    return false;
}
void Config::setIsApClientMode (bool val) {
    if (val) {
        p_config->isApClientMode = 1;
    } else {
        p_config->isApClientMode = 0;
    }
}
//
bool Config::getIsShowHome () {
    if (p_config->isShowHome == 1) {
        return true;
    }
    return false;
}
void Config::setIsShowHome (bool val) {
    if (val) {
        p_config->isShowHome = 1;
    } else {
        p_config->isShowHome = 0;
    }
    char value[128];
    snprintf(value, sizeof(value), "%d", p_config->isShowHome);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isShowHome", value);
}
//
int Config::getApClientMax () {
    return p_config->ApClientMax;
}
void Config::setApClientMax (int max) {
    p_config->ApClientMax = max;
    char value[128];
    snprintf(value, sizeof(value), "%d", p_config->ApClientMax);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApClientMax", value);
}
//
const char* Config::getApKeyType () {
    return p_config->ApKeyType;
}
void Config::setApKeyType (const char *type) {
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApKeyType", type);
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""setApKeyType,iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return;
    }
    strlcpy(p_config->ApKeyType, iniparser_getstring (ini, "httpd:ApKeyType", "psk2"), sizeof (p_config->ApKeyType));
    iniparser_freedict (ini);
}
//
const char* Config::getApKey () {
    return p_config->ApKey;
}
void Config::setApKey (const char *key) {
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ApKey", key);
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""setApKey,iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return;
    }
    strlcpy(p_config->ApKey, iniparser_getstring (ini, "httpd:ApKey", "12345678"), sizeof (p_config->ApKey));
    iniparser_freedict (ini);
}
//
bool Config::getIsUpdateLogOntime () {
    if (p_config->isUpdateLogOntime == 1) {
        return true;
    }
    return false;
}
void Config::setIsUpdateLogOntime (bool val) {
    if (val) {
        p_config->isUpdateLogOntime = 1;
    } else {
        p_config->isUpdateLogOntime = 0;
    }
    char value[128];
    snprintf(value, sizeof(value), "%d", p_config->isUpdateLogOntime);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "isUpdateLogOntime", value);
}
//
const char* Config::getMTKID () {
    return p_config->MTKID;
}
void Config::setMTKID (const char *id) {
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "MTKID", id);
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""setMTKID,iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return;
    }
    strlcpy(p_config->MTKID, iniparser_getstring (ini, "httpd:MTKID", "none"), sizeof (p_config->MTKID));
    iniparser_freedict (ini);
}
//
const char* Config::getBangZoneAddr () {
    return p_config->BangZoneAddr;
}
void Config::setBangZoneAddr (const char *addr) {
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "BangZoneAddr", addr);
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""setBangZoneAddr,iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return;
    }
    strlcpy(p_config->BangZoneAddr, iniparser_getstring (ini, "httpd:BangZoneAddr", "www.bangzone.cn"),
            sizeof (p_config->BangZoneAddr));
    iniparser_freedict (ini);
}
//
int Config::getBangZonePort () {
    return p_config->BangZonePort;
}
void Config::setBangZonePort (int port) {
    p_config->BangZonePort = port;
    char value[128];
    snprintf(value, sizeof(value), "%d", p_config->BangZonePort);
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "BangZonePort", value);
}
//
const char* Config::getEthStaticDns () {
    return p_config->ethStaticDns;
}
void Config::setEthStaticDns (const char *key) {
    ConfigSetKey (BBDOG_CONF_FILE, "httpd", "ethStaticDns", key);
    dictionary  *ini;
    ini = iniparser_load (BBDOG_CONF_FILE);
    if (ini == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""setEthStaticDns,iniparser_load failed!"GRAY, "config:");
        ERROR_LOG ("iniparser_load failed!");
        return;
    }
}
//
bool Config::getIsTestMode () {
    if (p_config->isTestMode == 1) {
        return true;
    }
    return false;
}
void Config::setIsTestMode (bool val) {
    if (val) {
        p_config->isTestMode = 1;
    } else {
        p_config->isTestMode = 0;
    }
}

Config g_config;
