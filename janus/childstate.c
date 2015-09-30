#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

#define __USE_GNU

#include <fcntl.h>
#include <unistd.h>

#include "debug.h"
#include "trace.h"


static char * starting_dir = NULL;
static char * * starting_env = NULL;

static int starting_uid;
static int starting_gid; 
/* static int starting_priority; */

#define MEG(x) (x * 1024 * 1024)

static struct {
#ifdef FILE_LIMITS
    int rlimit_fsize;
    int rlimit_nofile;
#endif
    int rlimit_data;    
    int rlimit_stack;
    int rlimit_rss;     
} limits = {
#ifdef FILE_LIMITS
    MEG(10),       /* Maximum filesize */
    1024,          /* max number of open files */
#endif
    MEG(50),       /* max data size */
    MEG(50),       /* max stack size */
    MEG(50),       /* max resident set size */
    };


//by default inherit from parent.
void init_childstate()
{
    starting_dir = NULL;
    starting_gid = getgid();
    starting_uid = getuid();
    /* starting_priority = getpriority(PRIO_PROCESS,getpid()); */
    starting_env = (char **)malloc(sizeof(char **));
    assert(starting_env);
    starting_env[0] = NULL;
}

extern char * * environ;

int childstate_putenv(char * str)
{
    char * tokptr;
    char * conf_line;
    char * * save_environ;

    if (!str) 
        return -1;

    conf_line = strdup(str); //note we don't free this
    assert(conf_line);

    tokptr = strtok(conf_line," \t");

    if (!tokptr)
        return -1;

    while (tokptr) {

        save_environ = environ;
        environ = starting_env;
        putenv(tokptr);
        starting_env = environ;
        environ = save_environ;
        
        tokptr = strtok(NULL," \t");
    }

    return 0;
}

int childstate_set_starting_dir(const char * dir)
{
    if (!dir) 
        return -1;
    
    if (starting_dir)
        free(starting_dir);

    starting_dir = strdup(dir);
    
    return 0;
    
}

int childstate_set_starting_gid(const char * group)
{
    struct group * gp;
    
    if (!group)
        return -1;

    gp = getgrnam(group);

    if(!gp) {
        PERROR("No such group %s",group);
        return -1;
    }

    starting_gid = gp->gr_gid;

    return 0;
    
}

int childstate_set_starting_uid(const char * user)
{
    struct passwd * pw;
    
    if (!user)
        return -1;

    pw = getpwnam(user);

    if(!pw) {
        PERROR("No such user %s",user);
        return -1;
    }

    starting_uid = pw->pw_uid;

    return 0;
}

int childstate_set_starting_priority(const char * pri)
{
    int priority;

    if (!pri)
        return -1;
    
    priority = atoi(pri);

    if ((priority > 20) || (priority < -20)) {
        PERROR("Invalid priority, legal range -20 to 20");
        return -1;
    }

    /* starting_priority = priority; */

    return 0;
}

    

int childstate_putrlimit(const char * str)
{
    char * type, * lim;
    char * conf_line;
    long tsize;
    char * endptr;

    if(!str) 
        return -1;
   
    conf_line = strdup(str);
    assert(conf_line);

        
    type = strtok(conf_line," \t");
    lim  = strtok(NULL," \t");

    if (!type || !lim) 
        goto exit_fail;

    
    tsize = strtol(lim,&endptr,10);

    if (*endptr || errno || (tsize < 0) || (tsize > 256)) {
        PERROR("invalid size to process_linit,valid range [0-256]");
        goto exit_fail; 
    }

#ifdef FILE_LIMITS
    if (!strcmp("MAX_FILE_SIZE",type))
        limits.rlimit_fsize = MEG(tsize);
    if (!strcmp("MAX_OPEN_FILES",type))
        limits.rlimit_nofile = tsize;
#endif

    if (!strcmp("MAX_DATA_SIZE",type))
        limits.rlimit_data = MEG(tsize);
    if (!strcmp("MAX_STACK_SIZE",type))
        limits.rlimit_stack = MEG(tsize);
    if (!strcmp("MAX_RSS_SIZE",type)) 
        limits.rlimit_rss = MEG(tsize);

    return 0;

    exit_fail:
        free(conf_line);
        return -1;
}


/* Put the child process into a clean state */
static void setup_state(int pipefd1, int pipefd2, int interactive)
{
    struct rlimit rl;
    int devnull;
    int fd;

    /* Set the umask */
    umask(077);

    /*set the resource limits */
    
#ifdef FILE_LIMITS
    rl.rlim_cur = rl.rlim_max = limits.rlimit_fsize;
    setrlimit(RLIMIT_FSIZE, &rl);
    
    rl.rlim_cur = rl.rlim_max =  limits.rlimit_nofile;
    setrlimit(RLIMIT_NOFILE, &rl);
#endif

    rl.rlim_cur = rl.rlim_max = limits.rlimit_data;
    if (setrlimit(RLIMIT_DATA, &rl))
        goto seterr;

    rl.rlim_cur = rl.rlim_max = limits.rlimit_stack;
    if(setrlimit(RLIMIT_STACK, &rl))
        goto seterr;

    /* Core dumps must not be allowed; they allow to bypass the path module. */
    rl.rlim_cur = rl.rlim_max = 0;
    if(setrlimit(RLIMIT_CORE, &rl))
        goto seterr;

    rl.rlim_cur = rl.rlim_max =  limits.rlimit_rss;
    if (setrlimit(RLIMIT_RSS, &rl))
        goto seterr;

    if (0) {
        seterr:
        PERROR("setrlimit error: %s",strerror(errno));
        exit(1);
    }

        /* setup our uid & gid  */
        /* Should we really be doing all this, or should we let some other
           program do all this uid-changing stuff?  I don't know. */
    {
        struct passwd * pw = getpwuid(starting_uid);
        uid_t nuid, neuid, nsuid;
        assert(pw);

        if (setgid(starting_gid)) {
            PERROR("setgid(%d) failed!",starting_gid);
            exit(1);
        }

        if (getgid() != starting_gid || getegid() != starting_gid) {
            PERROR("setgid(%d) failed to set all gid's!",starting_gid);
            exit(1);
        }

        /* Only report failure if we're root, since we don't expect
           this to succeed if we don't have root permissions. */
        if (initgroups(pw->pw_name, starting_gid) && geteuid() == 0) {
            PERROR("initgroups failed!");
            exit(1);
        }

        if (setuid(starting_uid)) {
            PERROR("setuid(%d) failed!",starting_uid);
            exit(1);
        }

        if (getresuid(&nuid, &neuid, &nsuid)) {
            PERROR("getresuid() failed!");
            exit(1);
        }

        if (nuid != starting_uid || neuid != starting_uid
                || nsuid != starting_uid) {
            PERROR("setuid(%d) failed to set all uids!",starting_uid);
            exit(1);
        }
    }

    /* set our priority */
    /* setpriority(PRIO_PROCESS,getpid(),starting_priority); */

    /* Get our own process group and session id */
    if (setsid() < 0) {
        assert(0);
    }
    
    /* Future: Kill all existing IPC maps? */

    assert(starting_dir);

    /* Make the dir in case it doesn't exist */
    (void) mkdir(starting_dir, 0700);

    /* Go to it */
    if (chdir(starting_dir) < 0) {
        if (errno == ENOENT)
            PERROR("Sandbox directory \"%s\" doesn't exist.\n"
                   "If the directory name is correct, use `mkdir -m 700 %s`;\n"
                   "otherwise, fix the policy file.",
                   starting_dir, starting_dir);
        else
            PERROR("chdir(\"%s\"): %s", starting_dir, strerror(errno));
        exit(1);
    }

    if (!interactive) {
        /* Close stdin/out/err */
        close(0);
        close(1);
        close(2);

        /* Get a /dev/null handle and make stdin/out/err it */
        devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
    }

    /* Close all remaining fds except for the sync pipe */
    if (getrlimit(RLIMIT_NOFILE, &rl))
        rl.rlim_max = 1024;

    for (fd = 3; fd < rl.rlim_max; ++fd) {
        if (fd != pipefd1 && fd != pipefd2)
            close(fd);
    }
}

void verify_startstate(void)
{
    int err = 0;

    if (!starting_dir) {
        PERROR("A starting_dir must be specified in your policy file.");
        err = 1;
    }

    if (geteuid() != 0 || getuid() != 0) {
        if (starting_uid != getuid() || starting_uid != geteuid()) {
            PERROR("Sorry janus must be run as root to use starting_uid.");
            err = 1;
        }
    }

    if (!limits.rlimit_data) {
        PERROR("process_limit MAX_DATA_SIZE must be set (size > 0) in policy file");
        err = 1;
    }
    
    if (!limits.rlimit_stack) {
        PERROR("process_limit MAX_STACK_SIZE must be set (size > 0) in policy file");
        err = 1;
    }
    
    if (!limits.rlimit_rss) {
        PERROR("process_limit MAX_RSS_SIZE must be set (size > 0) in policy file");
        err = 1;
    }

#ifdef FILE_LIMITS
    if (!limits.rlimit_fsize) {
        PERROR("Warning MAX_FILE_SIZE limit not set, assuming limit = 0, is
        this really what you want!");
    }


    if (!limits.rlimit_nofile) {
        PERROR("process_limit MAX_OPEN_FILES must be set (size > 0) in policy file");
        err = 1;
    }
#endif

    if (err)
        exit(1);
}

/* this is where the action gets started, spawn a new child 
to run command with the current child state and attach to 
it,errors here are basically fatal so no need to return anything 
*/

void childstate_start_child(char * path,char * * argv,int interactive)
{
   //two pairs of pipes for synchronization
    int attachpipe[2] = {-1, -1}, 
        runpipe[2] = {-1, -1};    
    char buf[10] = { '\n' };
    int pid,rv,err;

    
    /*preform final sanity checks before starting
      new child */
    verify_startstate();

    /* Make pipes */
    pipe(attachpipe);
    pipe(runpipe);

    /* Do the fork thing */
    pid = fork();

    if (!pid) {
        close(attachpipe[0]);
        close(runpipe[1]);

        //Get into a sane state
        setup_state(attachpipe[1], runpipe[0], interactive);

        //Signal the parent to attach
        rv = write(attachpipe[1], buf, 1);
        assert(rv == 1);
        close(attachpipe[1]);

        //Wait until the parent is ready
        rv = read(runpipe[0], buf, 1);
        assert(rv == 1);
        close(runpipe[0]);

        execve(path,argv,starting_env);

        if (errno == ENOENT)
            PERROR("Command not found: %s", argv[0]);
        else
            PERROR("execv(\"%s\") failed: %s", argv[0], strerror(errno));
        exit(1);

    } else {
        close(attachpipe[1]);
        close(runpipe[0]);

        /* Wait for the child to set its environment */
        if ((rv = read(attachpipe[0], buf, 1)) < 1) {
            /* We'll see an EOF (rv==0) if the child exited early on
               (before getting to the execv(), certainly).
               But we should never see a -1 error! */
            assert(rv == 0);
            exit(1);
        }
        close(attachpipe[0]);
    } 
    
    err = attach(pid);        //attach  to new proc

    if (err < 0) {
        kill(pid, SIGKILL);
        exit(1);
    }

    /* Wake it up */
    if (runpipe[1] >= 0) {
        write(runpipe[1], "\n", 1);
        close(runpipe[1]);
    }

}
