#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE_LEN  (1024*30)
#define DOWNLOAD_FILE_PATH  "/mnt/sdcard/media/"
#define DOWNLOAD_FILE_NAME  "bzmtk8_3_0.tgz"

static char download_file_path[256];
static char download_file_name[256];

static void ShowInfo (char * error) {
    printf ("Content-Type:text/html;charset=UTF-8\n\n");
    printf ("<center><font color='blue'>%s</font></center>" , error);
}

static void ShowErrorInfo (char * error) 
{
    printf ("Content-Type:text/html;charset=UTF-8\n\n");
    printf ("<center><font color='red'>%s</font></center>" , error);
}

int main() 
{
    FILE *fp;
    char filebuf[MAX_FILE_LEN];
    char cmd[512];
    struct stat sb;

    ///////////////////////////
    memset (download_file_path, 0, sizeof(download_file_path));
    memset (download_file_name, 0, sizeof(download_file_name));
    char *data = getenv ("QUERY_STRING");
    if (NULL == data) {
        ShowErrorInfo ("getenv failed!");
        return 0;
    }
    if (strstr (data, "filePath=")) {
        if (1 != sscanf (data, "filePath=%[^&]", download_file_path)) {
            ShowErrorInfo ("get filePaht failed!");
            return 0;
        }
    }
    char *p = NULL;
    if (p = strstr (data, "fileName=")) {
        if (1 != sscanf (p, "fileName=%[^&]", download_file_name)) {
            ShowErrorInfo ("get fileName failed!");
            return 0;
        }
    }
    //去掉download_file_path 最后面的'\'
    p = download_file_path + strlen (download_file_path) - 1;
    if (*p == '/') {
        *p = '\0';
    }
    strcat (download_file_path, "/");
    ///////////////////////////

    sprintf (cmd, "%s%s", download_file_path, download_file_name);
    stat (cmd, &sb); //取待下载文件的大小

    //输出HTTP头信息，输出附加下载文件、文件长度以及内容类型
    printf ("Content-Disposition:attachment;filename=%s", download_file_name);
    printf ("\r\n");
    printf ("Content-Length:%d", sb.st_size);
    printf ("\r\n");
    printf ("Content-Type:application/octet-stream\r\n");
    printf ("\r\n");
    sprintf (cmd, "%s%s", download_file_path, download_file_name);

    if (fp = fopen (cmd, "r+b")) {
        //成功打开文件，读取文件内容
        do {
            int rs = fread (filebuf, 1, sizeof (filebuf), fp);
            fwrite (filebuf, rs, 1, stdout);
        } while (!feof (fp));
        fclose (fp);
    }

    //ShowInfo ("ok");

    return 1;
}

