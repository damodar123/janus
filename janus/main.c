/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of his file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <syslog.h>
#include <fcap.h>
#include "trace.h"
#include "systable.h"
#include "module.h"
#include "debug.h"
#include "sysxlat.h"
#include "childstate.h"
#include "main.h"
#include "bsdstring.h"

/* globals -- shared with modules */

int debug = 0;
int verbose = 0;



/* deny and logging stuff */

static int show_denies = 0;
static int allow_everything = 0;
static int deny_level = 0;
static char deny_msg[MAX_DENY_MSG];
static int new_deny = 0;

static int log_level = DENY_DEFAULT;
static int kill_level = DENY_KILL;
static int shutdown_level = DENY_SHUTDOWN;

static void clear_deny()
{
    deny_level = 0;
    deny_msg[0] = '\0';
    new_deny = 0;
}

int deny(int level,char * fmt,...)
{
    va_list ap;

    if (deny_level < level) {
        va_start(ap,fmt);
        vsnprintf(deny_msg,sizeof(deny_msg),fmt,ap);
        va_end(ap);
        deny_level = level;
    }
    
    new_deny = 1;
    return DENY;
}

static int set_level(const char * lptr,int * level)
{
    if (!lptr) {
        PERROR("no level specified");
        return -1;
    } 

    if ((*level > 10) || (*level < 1)) {
        PERROR("Invalid level, valid levels are [1-10]");
        return -1;
    }

    return 0;
}

int main_set_kill_level(const char * conf)
{
   return set_level(conf,&kill_level);
}

int main_set_log_level(const char * conf)
{
   return set_level(conf,&log_level);
}

int main_set_shutdown_level(const char * conf)
{
   return set_level(conf,&shutdown_level);
}


void setup_config_init_tables(FILE * conf, actionlist systable[NSYSCALL],int show_policy);

static void usage(char *progname)
{
    fprintf(stderr, "Usage: %s [options] [-f policyfile] command\n",progname);
    fprintf(stderr, "%s -h for options.\n",progname);
    exit(1);
}

static void help(char * progname)
{
    static char  *help_msg[] = {
    "Options:",
    " -s      Show policy and exit.",
    " -h      Print help message",
    " -i      interactive; Bind stdin/stdout/stderr of traced process.",
    " -v      verbose; Show all system calls that are denied.",
    " -vv     very verbose; Output verbose listing of all traced process activity.",
    " -d      debug; Output debug information (useful mainly for coders).",
    "",
    "Extra options for debugging only:",
    "(Note: these options BYPASS SECURITY RESTRICTIONS and are thus INSECURE!)",
    " --trace-no-security      Always allow every system call, overriding the policy's restrictions.",
    "",
    "see the man page for additional details on options and policy.",
    0};
    char **p = help_msg;

    fprintf(stderr, "Usage: %s [options] [-f policyfile] command\n",progname);
    fprintf(stderr,"Version: %s (%s)\n", VERSION, __DATE__);
    while (*p)
        fprintf(stderr, "%s\n", *p++);
    exit(1);
}


#define STR_MAX 256

static void print_event(prstat_t prstat)
{
    char call_buff[STR_MAX];

    if (verbose) {
        if ((prstat.why == SYSENTRY) || (prstat.why == SYSEXIT)) {
            xlat_system_call(call_buff,sizeof(call_buff),prstat);
            fprintf(stderr,"[%d] %s\n",prstat.pid,call_buff);
        } else if (prstat.why == PROCESSEXIT) {
            fprintf(stderr,"[%d] exited...\n",prstat.pid);
        }
    }
}

static void allow_event(prstat_t *pr)
{
    assert(pr->why == SYSENTRY || pr->why == SYSEXIT);

    if (runtraced(pr->pcb, 0) < 0) {
        PERROR("runtraced failed while trying to allow %s: %s",
            xlat_callnum(pr->syscall), strerror(errno));
        if (pr->pcb)
            slay(pr->pcb);
        exit(1);
    }
}


static void deny_event(prstat_t *pr)
{
    char call_buff[STR_MAX];
    assert(pr->why == SYSENTRY);

    if(!new_deny) 
        strlcpy(deny_msg,"No message for this yet.",sizeof(deny_msg));

    /*    
    if (deny_level >= shutdown_level) {
        syslog(LOG_ALERT,"Denying(%d) %s() : %s\n",
        deny_level,xlat_callnum(pr->syscall),deny_msg);

        syslog(LOG_ALERT,"Shutting down application!!");
        slay(pr->pcb);
        exit(1);
    }
    
    if (deny_level >= kill_level) {
        syslog(LOG_WARNING,"Denying(%d) %s() : %s\n",
        deny_level,xlat_callnum(pr->syscall),deny_msg);

        syslog(LOG_WARNING,"Killing process!!");
        slay(pr->pcb);
    }

    if (deny_level >= log_level) {
       syslog(LOG_NOTICE,"Denying(%d) %s() : %s\n",
        deny_level,xlat_callnum(pr->syscall),deny_msg);
    }
    */
    
    xlat_system_call(call_buff,sizeof(call_buff),*pr);
    
    if (allow_everything) {
        fprintf(stderr,"Would Deny %s : %s\n",call_buff,deny_msg);
        allow_event(pr);
        return;
    } else if (show_denies) {
        fprintf(stderr,"Denying %s : %s\n",call_buff,deny_msg);
    }

    if (runtraced(pr->pcb, 1) < 0) {
        PERROR("runtraced failed on deny: %s",strerror(errno));
        if (pr->pcb)
            exit(1);
    }
}

static void check_syscall(prstat_t *pr,
                          actionlist systable[NSYSCALL])
                          
{
    int saw_allow = 0, saw_deny = 0, allow_it = 0;
    actionnode *anode;

    assert(pr && pr->pcb);
    assert(pr->syscall >= 0 && pr->syscall < NSYSCALL);

    /* Check all the hooks. */
    for (anode=systable[pr->syscall].head; anode; anode=anode->next) {
        int kind = anode->kind;

        /* Invoke handler if necessary. */
        if ((kind == FUNC && pr->why == SYSENTRY) ||
            (kind == EXIT_FUNC && pr->why == SYSEXIT)) 
            kind = (*anode->hook) (pr, anode->state);
        
        if (kind == DENY) {
            saw_deny = 1;
            /* One deny is enough to veto everything, so we don't need
               to invoke any more handlers. */
            break;
        } else if (kind == ALLOW) {
            saw_allow = 1;
        } else if (kind != NO_COMMENT) {
            PDEBUG("saw bogus action");
            assert(0);
        }
    }

    /* A single DENY counts as an unblockable veto, so the syscall will
       always be squashed if there are any DENY's.
       Otherwise, if there are no DENY's, then the syscall will be allowed
       to execute if there is at least one ALLOW.
       (If there are no DENY's and no ALLOW's, it'll be squashed.) */

    allow_it = !saw_deny && saw_allow;
    
    if (!allow_it && pr->why == SYSEXIT) {
        /* Wow, someone wants to DENY a system call _exit_?  Weird.
           Ok, kill the process; there's nothing else we can do. */
        PDEBUG("Denying on syscall exit for %s!", xlat_callnum(pr->syscall));
        if (pr->pcb)
            slay(pr->pcb);
    } else if (allow_it) {
        allow_event(pr);
    } else {
        if (!saw_deny)
            deny(DENY_DEFAULT,"No module allowed call.");

        deny_event(pr);
    }
}

static void run_sandbox(actionlist systable[NSYSCALL])
{
    prstat_t prstat;
    int rv;

    while (1) {
        rv = waitevent(&prstat);
        clear_deny();

        assert(rv >= 0);

        print_event(prstat);

        if ((prstat.why == SYSEXIT) || (prstat.why == SYSENTRY)) {
            check_syscall(&prstat, systable);
        } else if (prstat.why == PROCESSEXIT) {
            PDEBUG("%d pcbs in use", pcbsinuse());
            if (pcbsinuse() == 0) {
                PDEBUG("done.\n");
                exit(EXIT_SUCCESS);
            }
        } else {
            PDEBUG("Error: unrecognized event (why=%d)", prstat.why);
            if (prstat.pcb)
                slay(prstat.pcb);
            assert(0);
        }
    } 

}


int main(int argc, char **argv)
{
    FILE *cf;
    actionlist systable[NSYSCALL];
    char *configfname = "";
    char *janus_path;
    
    int interactive = 0;
    /* int original_env = 0; */
    int show_policy = 0;
    
    auto void strip_arg(int x);

    void strip_arg(int x) {
        if (argc > (x - 1)) {
            argc -= x;
            argv += x;
        } else
             usage(janus_path);
    }

    //grab progname
    janus_path = strdup(argv[0]);
    strip_arg(1);

    //No core dumps here kids...
    {
        struct rlimit rl;

        rl.rlim_cur = rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
    }

    /* Don't remove this check.
       We assume elsewhere that we've done this check. */
    if (getuid() != geteuid()) {
        fprintf(stderr, "Janus must not be run setuid!\n");
        exit(1);
    }
        
        
    //setup syslog
    /* openlog("janus",LOG_PERROR | LOG_NDELAY,LOG_AUTHPRIV); */

    /* Parse options */
    while (argc > 0 && argv[0][0] == '-') {

        /* give additional debugging info */
        if (!strcmp(argv[0], "-d")) {
            debug = 1;
            strip_arg(1);
        }
        
        /* Show all denied syscalls. */
        else if (!strcmp(argv[0], "-v")) {
            show_denies = 1;
            strip_arg(1);
        }

        /*detailed report of traced program behavior */
        else if (!strcmp(argv[0], "-vv")) {
            show_denies = 1;
            verbose = 1;
            strip_arg(1);
        }
        
        else if (!strcmp(argv[0], "--trace-no-security")) {
            /* allow all calls to procede */
            allow_everything = 1;
            strip_arg(1);
            fprintf(stderr, "WARNING: Using insecure option `--trace-no-security': allowing all system calls.\n");
        }

        else if (!strcmp(argv[0], "-i")) {
            interactive = 1;
            strip_arg(1);
        }
        
        else if (!strcmp(argv[0], "-s")) {
            show_policy = 1;
            strip_arg(1);
        }
        
        #ifdef INSECURE_FLAGS
            /* else if (!strcmp(argv[0], "-o")) { */
                /* original_env = 1; */
                /* strip_arg(1); */
                /* fprintf(stderr, "WARNING: Using insecure option `-o': using original environment.\n"); */
            /* } */
        #endif 

        else if (!strcmp(argv[0], "-f")) {
            configfname = argv[1];
            strip_arg(2);
        }

        else if (!strcmp(argv[0], "-h")) {
            help(janus_path);
        }
        else
            usage(janus_path);
    }

    /* Check args */
    if (argc < 1)
        usage(janus_path);

    /* make sure a config file has been given */
    if (strlen(configfname) == 0)
        usage(janus_path);

    {
        struct stat buff; 
        if (stat(argv[0],&buff) < 0) {
            if (errno == ENOENT)
                PERROR("Command not found: %s", argv[0]);
            else
                PERROR("Couldn't find command \"%s\": %s",argv[0],strerror(errno));
            exit(1);
        }
    }

    cf = fopen(configfname, "r");

    if (!cf) {
        if (errno == ENOENT)
            PERROR("Config file not found: %s", configfname);
        else
            PERROR("Couldn't open config file: %s", strerror(errno));
        exit(1);
    }

    /* Initialize the systable and load it up with the policy file/
    configure based on policy*/
    setup_config_init_tables(cf,systable,show_policy);

    if (show_policy)
        exit(EXIT_SUCCESS);

    fclose(cf);

    /* This is where all the fun stuff is */
    childstate_start_child(argv[0],argv,interactive);
    run_sandbox(systable);
    
    return 0;
}

#ifdef NDEBUG
#error Don't use NDEBUG!  We rely on assert()'s getting checked.
#error Using NDEBUG might make this thing insecure!!!
#endif
