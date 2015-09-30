/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <sys/syscall.h>
#include <linux/personality.h>
#include <asm/ipc.h>
#include <linux/ipc.h>

#include "module.h"
#include "sysxlat.h"
#include "bsdstring.h"
#include "debug.h"

/* Make sure there is no signed/unsigned funny-ness going on. */
static int pidok(pid_t pid, unsigned long arg) {
    if ((pid > 0) != (((int)pid) > 0))
        return 0;
    if ((pid > 0) != (((int)arg) > 0))
        return 0;
    if (arg != (unsigned long) pid)
        return 0;
    return 1;
}

static pid_t getchildpid(const pcb_t *pcb)
{
    pid_t pid = pcb->pid;
    assert(pid > 0);
    return pid;
}

/* Returns the pgrp associated with the traced process referred
   to by p.  This should change if/when we eliminate the pid field
   from pcb_t. */
static pid_t getchildpgrp(const pcb_t *pcb)
{
    pid_t pid = getchildpid(pcb);
    pid_t pgrp = __getpgid(pid);
    assert(pid > 0);
    assert(pgrp > 0);
    return pgrp;
}

/* Child process is allowed to do stuff to itself,
   or to any other processes we are currently tracing. */
static int pidallowed(const pcb_t *pcb, pid_t pid)
{
    if (pid == 0)
        return 1;
    return pid > 0 && (pid == getchildpid(pcb) || pid2pcb(pid) != NULL);
}

/* Child process is allowed to do stuff to its own pgrp.
   (We follow the convention that a process can either use its
   current pgid or else use its pid as its pgid.)

   This policy of letting it do stuff to its own pgrp is safe
   since we create a new pgrp for the application before forking
   it off.  Consequently, there's no danger that the child's pgrp
   might include processes outside the sandbox. */
static int pgrpallowed(const pcb_t *pcb, pid_t pgrp)
{
    if (pgrp == 0 || (pgrp > 0 && pgrp == getchildpid(pcb)))
        return 1;
    return pgrp == getchildpgrp(pcb);
}

static action	kill_hook(const prstat_t *p, void *unused)
{
    pid_t pid = (pid_t)p->args[0];

    if (!pidok(pid, p->args[0])) 
        return deny(DENY_DEFAULT,"Possible pid-casting attack.");
    if (pid > 0 && pidallowed(p->pcb, pid))
        return ALLOW;
    if (pid <= 0 && pgrpallowed(p->pcb, -pid))
        return ALLOW;
    return deny(DENY_DEFAULT,"Tried to kill process outside of sandbox.");
}

static action	getpgid_hook(const prstat_t *p, void *unused)
{
    pid_t pid = (pid_t)p->args[0];

    if (!pidok(pid, p->args[0]))
        return deny(DENY_DEFAULT, "Possible pid-casting attack.");

    /* Ok for app to get the pgid of its own process or of some other
       traced process, but not to query the pgid of outside third-party
       processes. */
    if (pid == 0 || pidallowed(p->pcb, pid))
        return ALLOW;

    return deny(DENY_DEFAULT,
        "Tried to get pgrp of external process (pid %d).", pid);
}

static action	setpgid_hook(const prstat_t *p, void *unused)
{
    pid_t pid = (pid_t)p->args[0], pgrp = (pid_t)p->args[1];

    if (!pidok(pid, p->args[0]) || !pidok(pgrp, p->args[1]))
        return deny(DENY_DEFAULT, "Possible pid-casting attack.");

    /* Only ok for child to change the pgrp of its own process
       or of some other traced process, but not to change the pgrp
       of some outside third-party process. */
    if (!(pid == 0 || pidallowed(p->pcb, pid)))
        return deny(DENY_DEFAULT,
            "Tried to change pgrp of external process (pid %d).", pid);

    /* Ok for child to set its pgrp to its own pid, or to leave it unchanged. */
    if (!pgrpallowed(p->pcb, pgrp))
        return deny(DENY_DEFAULT,
            "Not allowed to change pgrp of pid %d to %d.", pid, pgrp);

    return ALLOW;
}

static action	fork_exit_hook(const prstat_t *p, void *unused)
{
    int err;
    pid_t newpid = (pid_t) p->rv;

    if (!pidok(newpid, (unsigned long)p->rv)) 
        return deny(DENY_DEFAULT,"Possible pid-casting attack.");

    if (newpid > 0) {
        PDEBUG("fork called");
        err = attach(newpid);

        if (err < 0) {
            /* will slay the parent process */
            return deny(DENY_DEFAULT, "Couldn't attach to fork()d child!");
        }
    }

    return(ALLOW);
}

static action personality_hook(const prstat_t *p, void *unused)
{
    if (p->args[0] == PER_LINUX)
        return ALLOW;
    
    return deny(DENY_DEFAULT,"Invalid personality");
}    


/* syscalls I don't understand; thus deny & wait & see if anything breaks */
#define UNKNOWN DENY

static action    fcntl_hook(const prstat_t *p, void *unused)
{
    switch(p->args[1]) {
        case F_SETFL: {
            unsigned int new_mode = p->args[2], old_mode,
                old_acc_mode, new_acc_mode;

            if (fetch_fd_flags(p->pcb,p->args[0],&old_mode)) 
                return deny(DENY_DEFAULT,"Unable to read syscall argument.");
            
            /* Disallow changing access mode (e.g., O_RDONLY -> RDWR) */
            old_acc_mode = old_mode & O_ACCMODE;
            new_acc_mode = new_mode & O_ACCMODE;

            if (old_acc_mode == new_acc_mode ||
                (old_acc_mode == O_RDWR &&
                  (new_acc_mode == O_RDONLY || new_acc_mode == O_WRONLY))) {
                /* It's ok to drop read or write capability on an open fd. */
            } else {
                /* It's not ok to, e.g., add write mode to a read-only fd. */
                char msg[256];
                snprintf(msg, sizeof(msg),
                    "Not allowed to increase access mode from %s -> ", 
                    xlat_openmodes(old_acc_mode));
                strlcat(msg, xlat_openmodes(new_acc_mode), sizeof(msg));
                return deny(DENY_DEFAULT, msg);
            }

            /* Disallow changing anything other than O_APPEND or O_NONBLOCK */
            new_mode &= ~(O_APPEND|O_NONBLOCK|O_ACCMODE);
            old_mode &= ~(O_APPEND|O_NONBLOCK|O_ACCMODE);
            if (new_mode || new_mode != old_mode)
                return deny(DENY_DEFAULT,"Not allowed to change %s flags.",
                    xlat_openmodes(new_mode));
            return(ALLOW);
        }

        case F_DUPFD: return(ALLOW);
        case F_GETFL: return(ALLOW);

        /* set/get fd-close-on-exec flag is fine */
        case F_GETFD: return(ALLOW);
        case F_SETFD: return(ALLOW);
        /* set/get advisory locks are ok */
        case F_GETLK: return(ALLOW);
        case F_SETLK: return(ALLOW);
        case F_SETLKW: return(ALLOW);

        /* ok to get who receives signals for this fd */
        case F_GETOWN: return(ALLOW);

/* It should be safe to enable this code if anyone needs this functionality */
#ifdef notyet
        /* ok to set signal-recipient to p if ok to kill p */
        case F_SETOWN: {
            pid_t pid = (pid_t)p->args[2];

            if (!pidok(pid, p->args[2])) 
                return deny(DENY_DEFAULT,"Possible pid-casting attack.");
            if (pid == 0)
                return deny(DENY_DEFAULT, "F_SETOWN 0: should never happen (bug?).");
            if (pid > 0 && pid == getchildpid(p->pcb))
                return ALLOW;
            if (pid < 0 && pgrpallowed(p->pcb, -pid))
                return ALLOW;
            return deny(DENY_DEFAULT, "Unsafe F_SETOWN: might allow killing other processes.");
        }
#endif

        default: 
            return deny(DENY_DEFAULT,"Unknown cmd.");
    }
}

/* Philosophy: It's ok to get a copy of the state, but not to set state. */
static action    ioctl_hook(const prstat_t *p, void *unused)
{
    switch(p->args[1]) {
        case TIOCGPGRP: case FIONBIO: case FIONREAD: case TIOCGWINSZ:
        case TCGETS: case TCGETA:
            return(ALLOW);

        case TIOCSPGRP: 
            return deny(DENY_DEFAULT, "Tried to change tty's pgrp.");
        case TCSETS: 
            return deny(DENY_DEFAULT, "Tried to set tty's termios settings.");
        case TIOCSTI:
            return deny(DENY_DEFAULT, "Tried to stuff bytes into tty input stream (possible attack!).");

        case SIOCGIFCONF:       /* get iface list */
        case SIOCGIFNETMASK:    /* get network PA mask */
        case SIOCGIFNAME:       /* get iface name */
        case SIOCGIFFLAGS:      /* get flags */
        case SIOCGIFADDR:       /* get PA address */
        case SIOCGIFDSTADDR:    /* get remote PA address */
            return ALLOW;
    }

    return(NO_COMMENT);
}

static action	ulimit_hook(const prstat_t *p, void *unused)
{
    return deny(DENY_DEFAULT,"Obsolete syscall.");
}

static action	nice_hook(const prstat_t *p, void *unused)
{
    int inc = (int)p->args[0];

    if (inc >= 0 && inc <= 20) 
        return ALLOW;

    return deny(DENY_DEFAULT,"Tried to raise priority.");
}


static action ipc_hook(const prstat_t * p, void * unused)
{
    unsigned int call = (unsigned int)p->args[0];
    unsigned long key = p->args[1];

    if (p->args[0] >> 16 || call >> 16)
        return deny(DENY_DEFAULT, "Unexpected high bits in call (buggy app?).");
    call &= 0xffff;

/* enable this if needed */
#ifdef NOT_SUPPORTED_YET 
    switch(call) {
        case SEMOP:
        case SEMCTL:
            return ALLOW;

        /* A lovely misfeature of Linux: Apparently other processes
           can still get access to IPC_PRIVATE message queues.  Argh! */
        case SEMGET:
            if (key == IPC_PRIVATE)
                return ALLOW;
            else
                return deny(DENY_DEFAULT,"Tried to get non-private semaphore");

        case MSGSND:
        case MSGRCV:
        case MSGCTL:
            return ALLOW;

        case MSGGET:
            if (key == IPC_PRIVATE)
                return ALLOW;
            else
                return deny(DENY_DEFAULT,"Tried to get non-private message queue.");
    }
#endif

    switch(call) {
        /* Once a process has access to a shared memory segment,
           it is allowed to do what it wants with it. */
        case SHMAT:
        case SHMDT:
        case SHMCTL:
            return ALLOW;

        case SHMGET:
            if (key == IPC_PRIVATE)
                return ALLOW;
            else
                return deny(DENY_DEFAULT,"Tried to get non-private shared memory segment.");
    }
   
    return deny(DENY_DEFAULT,
        (call < SEMCTL) ? "Unrecognized semaphore op." :
        (call < MSGCTL) ? "Unrecognized message-queue op." :
        (call < SHMCTL) ? "Unrecognized shared memory call." :
        "Unrecognized IPC call.");
}


static int loaded = 0;

static void *	init(const char *conf_line)
{
    if (loaded) {
        PERROR("basic already loaded!!!");
        return INIT_FAIL;
    }

    loaded = 1;

    return NULL;
}

static const syscall_entry     entries[] = {


/*****UID/GID group********/

    {SYS_getuid, ALLOW, 0},
    {SYS_getgid, ALLOW, 0},
    {SYS_getegid, ALLOW, 0},
    {SYS_getgroups, ALLOW, 0},
    {SYS_geteuid, ALLOW, 0},
    {SYS_getresuid, ALLOW, 0},
    {SYS_getresgid, ALLOW, 0},

/*****SIGNALS group************/

    {SYS_kill, FUNC, kill_hook},
    {SYS_alarm, ALLOW, 0}, 
    {SYS_pause, ALLOW, 0}, 
    {SYS_signal, ALLOW, 0}, 
    {SYS_sigprocmask, ALLOW, 0}, 
    {SYS_sigsuspend, ALLOW, 0}, 
    {SYS_sigaction, ALLOW, 0}, 
    {SYS_sigpending, ALLOW, 0}, 
    {SYS_rt_sigaction, ALLOW, 0}, 
    {SYS_rt_sigprocmask, ALLOW, 0}, 

    {SYS_rt_sigsuspend, ALLOW, 0},  // NOTE: FCAP does not support trapping 
    {SYS_sigreturn, ALLOW, 0},   //       these calls.
    
/*****MEMORY group*************/

    {SYS_brk, ALLOW, 0}, 
    {SYS_mmap, ALLOW, 0}, 
    {SYS_mprotect, ALLOW, 0}, 
    {SYS_munmap, ALLOW, 0}, 
    
/*****SLEEP group************/    
    
    {SYS_nanosleep, ALLOW, 0},   
   
/*****System INFO group****/

    {SYS_uname, ALLOW, 0}, 
    {SYS_times, ALLOW, 0}, 
    {SYS_gettimeofday, ALLOW, 0}, 
    {SYS_time, ALLOW, 0}, 
    {SYS_ftime, ALLOW, 0},

/*****TIMER group***********/    

    {SYS_profil, ALLOW, 0}, 
    {SYS_getitimer, ALLOW, 0}, 
    {SYS_setitimer, ALLOW, 0}, 
    
/*****Personality group*******/
    
    {SYS_personality, FUNC, personality_hook}, 

/*****ipc group*******/
    {SYS_ipc,FUNC,ipc_hook},

/*****PROCESSES group*******/

    {SYS_exit, ALLOW, 0},
    {SYS_vfork, ALLOW, 0},
    {SYS_vfork, EXIT_FUNC, fork_exit_hook},
    {SYS_fork, ALLOW, 0},
    {SYS_fork, EXIT_FUNC, fork_exit_hook},
    {SYS_waitpid, ALLOW, 0},
    {SYS_wait4, ALLOW, 0},
    {SYS_getpid, ALLOW, 0},
    {SYS_getppid, ALLOW, 0},
    
    /****process groups ****/
    {SYS_setpgid, FUNC, setpgid_hook},
    {SYS_getpgrp, ALLOW, 0},
    {SYS_getpgid, FUNC, getpgid_hook},
   
   /***sessions***/
    {SYS_getsid, ALLOW, 0},
    {SYS_setsid, ALLOW, 0},

 /*****Resource limit group ****/

    {SYS_nice, FUNC, nice_hook},
    {SYS_ulimit, FUNC, ulimit_hook},
    {SYS_getrlimit, ALLOW, 0},
    {SYS_getrusage, ALLOW, 0},

 /*****FD group*******/  //messing with file contents is fine

    {SYS_pread,ALLOW,0},
    {SYS_pwrite,ALLOW,0},
    {SYS__newselect, ALLOW, 0},
    {SYS_poll, ALLOW, 0},
    {SYS_read, ALLOW, 0},
    {SYS_write, ALLOW, 0},
    {SYS_readv, ALLOW, 0},
    {SYS_writev, ALLOW, 0},
    {SYS_lseek, ALLOW, 0},
    {SYS_dup, ALLOW, 0},
    {SYS_dup2, ALLOW, 0},
    {SYS_pipe, ALLOW, 0},
    {SYS_flock, ALLOW, 0},
    {SYS_fcntl, FUNC,fcntl_hook},
    {SYS_getdents, ALLOW, 0},
    {SYS_getcwd,ALLOW,0},
    {SYS_ioctl, FUNC, ioctl_hook},
    {SYS__llseek, ALLOW, 0},
    {SYS_fsync, ALLOW, 0}, 


    };
static const int		nentries = sizeof(entries) / sizeof(syscall_entry);

 
void * basic_init(const char * conf) { return init(conf); }
int basic_num_entries() { return nentries; }
const syscall_entry * basic_get_entries() { return entries; }
