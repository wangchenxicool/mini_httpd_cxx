/**
 * @file main.c
 * @brief
 * @author wcx, wang_chen_xi_cool@qq.com
 * @version 0.1.0
 * @date 2017-11-02
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "my_popen.h"

#define DEAL_BUF_LEN    1024
#define SIGN_CODE_LEN   100
#define FILE_NAME_LEN   64

/* #define FILE_SAVE_DIR "/home/download/" */
#define FILE_SAVE_DIR "../"

enum {
    STATE_START,
    STATE_GET_SIGN_CODE,
    STATE_GET_FILE_NAME,
    STATE_GET_FILE_START,
    STATE_GET_FILE_CONTENT,
    STATE_CHECK_END,
    STATE_END
};

/***************************************************************************
  ShowErrorInfo
 ****************************************************************************/
static void ShowErrorInfo (char * error) {
    printf ("Content-Type:text/html;charset=UTF-8\n\n");
    printf ("<center><font color='red'>%s</font></center>" , error);
}

static void ShowInfo (char * error) {
    printf ("Content-Type:text/html;charset=UTF-8\n\n");
    printf ("<center><font color='blue'>%s</font></center>" , error);
}


int main (void) 
{
    FILE *fp; // 文件指针，保存我们要获得的文件
    int getState = STATE_START;
    int contentLength; // 标准输入内容长度
    int nowReadLen;
    int signCodeLen;
    int tmpLen;
    char *nowReadP;
    char *nowWriteP;
    char dealBuf[DEAL_BUF_LEN];
    char signCode[SIGN_CODE_LEN]; // 存储本次的特征码
    char tmpSignCode[SIGN_CODE_LEN];
    char fileName[FILE_NAME_LEN];
    char fileNameWcxAdd[FILE_NAME_LEN];
    memset (dealBuf, 0, DEAL_BUF_LEN);
    memset (signCode, 0, SIGN_CODE_LEN);
    memset (fileName, 0, FILE_NAME_LEN);
    nowReadLen = 0;

    ///////////////////////////
    char *data = getenv ("QUERY_STRING");
    if (NULL == data) {
        ShowErrorInfo ("getenv failed!");
        return 0;
    }
    if (strstr (data, "filename=")) {
        sscanf (data, "filename=%[^&]", fileNameWcxAdd);
    } else {
        snprintf (fileNameWcxAdd, sizeof(fileNameWcxAdd), "../tmp.txt");
    }
    ///////////////////////////

    if ( (char *) getenv ("CONTENT_LENGTH") != NULL) {
        contentLength = atoi ( (char *) getenv ("CONTENT_LENGTH"));
    } else {
        ShowErrorInfo ("No recovery data!");
        exit (1);
    }

    while (contentLength > 0) {

        if (contentLength >= DEAL_BUF_LEN) {
            nowReadLen = DEAL_BUF_LEN;
        } else {
            nowReadLen = contentLength;
        }
        contentLength -= nowReadLen;
        if (fread (dealBuf, sizeof (char), nowReadLen, stdin) != nowReadLen) {
            ShowErrorInfo ("Failed to read recovery data, please try again!");
            exit (1);
        }
        nowReadP = dealBuf;

        while (nowReadLen > 0) {
            switch (getState) {
                case STATE_START:
                    nowWriteP = signCode;
                    getState = STATE_GET_SIGN_CODE;

                case STATE_GET_SIGN_CODE:
                    if (strncmp (nowReadP, "\r\n", 2) == 0) {
                        signCodeLen = nowWriteP - signCode;
                        nowReadP++;
                        nowReadLen--;
                        *nowWriteP = 0;
                        getState = STATE_GET_FILE_NAME;
                        // ShowErrorInfo(signCode);
                    } else {
                        *nowWriteP = *nowReadP;
                        nowWriteP++;
                    }
                    break;

                case STATE_GET_FILE_NAME:
                    if (strncmp (nowReadP, "filename=", strlen ("filename=")) == 0) {
                        nowReadP += strlen ("filename=");
                        nowReadLen -= strlen ("filename=");
                        nowWriteP = fileName + strlen (FILE_SAVE_DIR);
                        while (*nowReadP != '\r') {
                            if (*nowReadP == '\\' || *nowReadP == '/') {
                                nowWriteP = fileName + strlen (FILE_SAVE_DIR);
                            } else if (*nowReadP != '\"') {
                                *nowWriteP = *nowReadP;
                                nowWriteP++;
                            }
                            nowReadP++;
                            nowReadLen--;
                        }
                        *nowWriteP = 0;
                        nowReadP++;
                        nowReadLen--;
                        getState = STATE_GET_FILE_START;
#if 0
                        memcpy (fileName, FILE_SAVE_DIR, strlen (FILE_SAVE_DIR));
#else
                        snprintf (fileName, sizeof(fileName), fileNameWcxAdd);
#endif
                        if ( (fp = fopen (fileName, "w")) == NULL) {
                            fprintf (stderr, "open file error\n");
                            exit (1);
                        }
                        //ShowErrorInfo(fileName);
                    }
                    break;

                case STATE_GET_FILE_START:
                    if (strncmp (nowReadP, "\r\n\r\n", 4) == 0) {
                        nowReadP += 3;
                        nowReadLen -= 3;
                        getState = STATE_GET_FILE_CONTENT;
                        //ShowErrorInfo("get");
                    }
                    break;

                case STATE_GET_FILE_CONTENT:
                    if (*nowReadP != '\r') {
                        fputc (*nowReadP, fp);
                    } else {
                        if (nowReadLen >= (signCodeLen + 2)) {
                            if (strncmp (nowReadP + 2, signCode, signCodeLen) == 0) {
                                getState = STATE_END;
                                nowReadLen = 1;
                                ShowInfo ("Data upload success!");
                                my_system ("chmod 777 /data/door_ctrl.db;sync");
                                /* if( system( "/var/landog/app/sniff/db_recover.sh" ) == 0 ){
                                   ShowErrorInfo( "数据库恢复完成，请重新启动landog" );
                                   }else{
                                   ShowErrorInfo( "数据库恢复过程中出现错误，错误原因：恢复的文件已经损坏" );
                                   }
                                   */
                            } else {
                                fputc (*nowReadP, fp);
                            }
                        } else {
                            getState = STATE_CHECK_END;
                            nowWriteP = tmpSignCode;
                            *nowWriteP = *nowReadP;
                            nowWriteP++;
                            tmpLen = 1;
                        }
                    }
                    break;

                case STATE_CHECK_END:
                    if (*nowReadP != '\r') {
                        if (tmpLen < signCodeLen + 2) {
                            *nowWriteP = *nowReadP;
                            nowWriteP++;
                            tmpLen++;
                            if (tmpLen == signCodeLen + 2) {
                                *nowWriteP = 0;
                                if ( (tmpSignCode[1] == '\n') && (strncmp (tmpSignCode + 2, signCode, signCodeLen) == 0)) {
                                    getState = STATE_END;
                                    nowReadLen = 1;
                                    ShowInfo ("Data upload success");
                                    /* if( system( "/var/landog/app/sniff/db_recover.sh" ) == 0 ){
                                       ShowErrorInfo( "数据库恢复完成，请重新启动landog" );
                                       }else{
                                       ShowErrorInfo( "数据库恢复过程中出现错误，错误原因：恢复的文件已经损坏" );
                                       }
                                       */
                                } else {
                                    //fprintf(fp,tmpSignCode);
                                    fwrite (tmpSignCode, sizeof (char), tmpLen, fp);
                                    getState = STATE_GET_FILE_CONTENT;
                                }
                            }
                        }
                    } else {
                        *nowWriteP = 0;
                        //fprintf(fp,tmpSignCode);
                        fwrite (tmpSignCode, sizeof (char), tmpLen, fp);
                        nowWriteP = tmpSignCode;
                        *nowWriteP = *nowReadP;
                        nowWriteP++;
                        tmpLen = 1;
                    }
                    break;

                case STATE_END:
                    nowReadLen = 1;
                    break;

                default:
                    break;
            }
            nowReadLen--;
            nowReadP++;

        } //end while

    } //end while

    if (fp != NULL) {
        fclose (fp);
    }
    return 0;
}

