#include "my_popen.h"

#define ANDROID

#ifdef ANDROID
#define	SHELL	        "/system/bin/sh"
#else
#define	SHELL	        "/bin/sh"
#endif
#define OPEN_MAX_GUESS  256

static pid_t	*childpid = NULL;
static int		maxfd;	/* from our open_max(), {Prog openmax} */


#ifdef   OPEN_MAX
static int openmax = OPEN_MAX;
#else
static int openmax = 0;
#endif

static int open_max (void) {
    if (openmax == 0) {
        errno = 0;

        if ( (openmax = sysconf (_SC_OPEN_MAX)) < 0) {
            if (errno == 0) {
                openmax = OPEN_MAX_GUESS;
            }
            else {
                perror ("sysconf error for _SC_OPEN_MAX");
            }
        }
    }
    return (openmax);
}

FILE * my_popen (const char *cmdstring, const char *type) {
    int		i, pfd[2];
    pid_t	pid;
    FILE	*fp;
    int     status;

    /* only allow "r" or "w" */
    if ( (type[0] != 'r' && type[0] != 'w') || type[1] != 0) {
        errno = EINVAL;		/* required by POSIX.2 */
        return (NULL);
    }

    if (childpid == NULL) {		/* first time through */
        /* allocate zeroed out array for child pids */
        maxfd = open_max();
        if ( (childpid = (pid_t *) calloc (maxfd, sizeof (pid_t))) == NULL) {
            return (NULL);
        }
    }

    if (pipe (pfd) < 0) {
        return (NULL);	/* errno set by pipe() */
    }

    if ( (pid = fork()) < 0) {
        return (NULL);	/* errno set by fork() */
    }
    else if (pid == 0) {	/* child */
        if (*type == 'r') {
            close (pfd[0]);
            if (pfd[1] != STDOUT_FILENO) {
                dup2 (pfd[1], STDOUT_FILENO);
                close (pfd[1]);
            }
        } else {
            close (pfd[1]);
            if (pfd[0] != STDIN_FILENO) {
                dup2 (pfd[0], STDIN_FILENO);
                close (pfd[0]);
            }
        }
        /* close all descriptors in childpid[] */
        for (i = 0; i < maxfd; i++) {
            if (childpid[ i ] > 0) {
                close (i);
            }
        }

#if 0
        execl (SHELL, "sh", "-c", cmdstring, (char *) 0);
#else
        const char *new_argv[4];
#ifdef ANDROID
        new_argv[0] = "/system/bin/sh";
#else
        new_argv[0] = "/bin/sh";
#endif
        new_argv[1] = "-c";
        new_argv[2] = cmdstring;
        new_argv[3] = NULL;
#ifdef ANDROID
        if (execvp ("/system/bin/sh", (char * const *) new_argv) == -1)   /* execute the command  */
#else
        if (execvp ("/bin/sh", (char * const *) new_argv) == -1)   /* execute the command  */
#endif
        {
            printf ("execvp()");
        } else {
            printf ("execvp() failed");
        }
#endif
        _exit (127);
    }

    /* parent */
    waitpid (pid, &status, 0);
    if (*type == 'r') {
        close (pfd[1]);
        if ( (fp = fdopen (pfd[0], type)) == NULL) {
            return (NULL);
        }
    } else {
        close (pfd[0]);
        if ( (fp = fdopen (pfd[1], type)) == NULL) {
            return (NULL);
        }
    }
    childpid[fileno (fp)] = pid;	/* remember child pid for this fd */
    return (fp);
}

int my_pclose (FILE *fp) {
    int		fd, stat;
    pid_t	pid;

    if (childpid == NULL) {
        return (-1);		/* popen() has never been called */
    }

    fd = fileno (fp);
    if ( (pid = childpid[fd]) == 0) {
        return (-1);		/* fp wasn't opened by popen() */
    }

    childpid[fd] = 0;
    if (fclose (fp) == EOF) {
        return (-1);
    }

    while (waitpid (pid, &stat, 0) < 0) {
        if (errno != EINTR) {
            return (-1);	/* error other than EINTR from waitpid() */
        }
    }

    return (stat);	/* return child's termination status */
}

int my_system (const char * cmd) {
    FILE * pp;
    pp = my_popen (cmd, "r");
    if (!pp) {
        perror ("my_popen");
        return -1;
    }
    my_pclose (pp);
    return 0;
}

static pid_t safe_fork (void) {
    pid_t result;
    result = fork();

    if (result == -1) {
        printf ("Failed to fork Bailing out");
        exit (1);
    } else if (result == 0) {
    }

    return result;
}

#if 0
int execute (const char *cmd_line, int quiet) {
    int pid,
        status,
        rc;

    const char *new_argv[4];
#ifdef ANDROID
    new_argv[0] = "/system/bin/sh";
#else
    new_argv[0] = "/bin/sh";
#endif
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    pid = safe_fork();
    if (pid == 0) {    /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet) close (2);
#ifdef ANDROID
        if (execvp ("/system/bin/sh", (char * const *) new_argv) == -1)   /* execute the command  */
#else
        if (execvp ("/bin/sh", (char * const *) new_argv) == -1)   /* execute the command  */
#endif
        {
            printf ("execvp()");
        } else {
            printf ("execvp() failed");
        }
        exit (1);
    }

    /* for the parent:      */
    //printf ("Waiting for PID %d to exit\n", pid);
    rc = waitpid (pid, &status, 0);
    //printf ("Process PID %d exited\n", rc);

    return (WEXITSTATUS (status));
}
#endif
