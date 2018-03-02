#include <syslog.h>
#include "terminal_color.h"
#include "wcx_log.h"
#include "my_popen.h"

int my_system (const char * cmd)
{
    FILE *fp;
    int res;
    char buf[512];

    if (cmd == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""cmd is NULL"GRAY, "my_system:");
        WARNING_LOG ("cmd is NULL");
        return -1;
    }

    if ((fp = popen (cmd, "r")) == NULL) {
        syslog (LOG_DEBUG, RED"%-15s""popen: %s"GRAY, "my_system:", strerror(errno));
        WARNING_LOG ("popen error: %s", strerror (errno));
        return -1;
    }

     while (fgets (buf, sizeof (buf), fp)) {
//         printf ("fgets:%s", buf);
     }

    if ((res = pclose (fp)) == -1) {
        syslog (LOG_DEBUG, RED"%-15s""pclose: %s"GRAY, "my_system:", strerror(errno));
        WARNING_LOG ("pclose error:%s", strerror (errno));
        return res;
    }

    return 0;
}
