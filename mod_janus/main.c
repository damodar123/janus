
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <linux/kernel.h>       /* [KEN] These are needed to make kernel modules */
#include <linux/module.h>
#include <linux/version.h>

#include <linux/errno.h>
#include <linux/signal.h>        //signal delivery
#include <linux/poll.h>            /* support for poll */
#include <linux/sched.h>        /* for wait queues and current  and find_task */
#include <linux/fs.h>            /* for file op stuff */
#include <linux/types.h>        /* size_t */
#include <linux/sys.h>
#include <linux/ptrace.h>        /* pt_regs etc. */
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <linux/string.h>        /*helpful string and mem ops */
#include <linux/utime.h>
#include <linux/file.h>         /*stuff for accessing socket info */
#include <linux/net.h>         /*so we know what a socket looks like */

#include <asm/segment.h>        /* for copy to and from user */
#include <asm/uaccess.h>        /* for copy to and from user */
#include <asm/unistd.h>            /* for system call numbers */
#include <asm/semaphore.h>        


#include <sys/syscall.h>        /* system call #s */

static char __modversion[] = "$Id: main.c,v 1.22 2000/08/11 22:48:27 talg Exp $";

char kernel_version[] = UTS_RELEASE;

#include "fcap.h"
#include "fcap_kernel.h"
#include "modtools.h"
#include "callnames.h"
#include "lock.h"
#include "task.h"

//define static to be blank (see below) to reveal helpful symbol info
//#define STATIC static
#define STATIC 

// to watch return values with RETURN define SHOW_EXIT

asmlinkage int fcap_check_call(struct pt_regs regs);

/* actual system call replacement, defined in ent.S */
extern asmlinkage int syscall_redirect(struct pt_regs);


/*sock stuff */
struct socket * lookup_socket(struct task_struct * tp, int fd, int *err);
struct file * get_file(struct task_struct * tp, int fd, int *err);

/* Each traced process has a monitor associated 
with it that keeps track of its current state */

typedef struct __monitor_state {
    mybool attached;
    /* Remaining fields are valid only if attached is true.
       Note that once attached becomes true, it never gets reset to false. */
    int pid;
    trap_set enter_traps;
    trap_set exit_traps;
    mybool event_pending;
    request_t pending_request; /* Only valid if event_pending is true. */
    volatile mybool syscall_blocked;
    mybool proc_exited;
    int next_action;
    struct wait_queue *blocked_syscall;
    struct wait_queue *blocked_read;
    arglock_t lock;
} monitor_state;

/* possible monitor events are system call EXIT,ENTRY and process death */

STATIC int EVENT_PENDING_P(monitor_state * this_monitor)
{
    return this_monitor->event_pending;
}

STATIC void SET_EVENT_PENDING(monitor_state * this_monitor)
{
    this_monitor->event_pending = TRUE;
}

STATIC void CLEAR_EVENT_PENDING(monitor_state * this_monitor)
{
    this_monitor->event_pending = FALSE;
}

/* reading/waiting for an event on a monitor is interruptible */
STATIC void READ_SLEEP_ON(monitor_state * this_monitor)
{
    SLEEP_ON_LIGHT(&this_monitor->blocked_read);
}

STATIC void READ_WAKE_UP(monitor_state * this_monitor)
{
    PDEBUG("read wakeup called by %d:%p",current->pid,this_monitor);
    WAKE_UP_LIGHT(&this_monitor->blocked_read);
}

/* If a process traps on a system call it cannot be interrupted */
STATIC void SYSCALL_WAKE_UP(monitor_state * this_monitor)
{
    PDEBUG("SYSCALL wakeup called");
    WAKE_UP_DEEP(&this_monitor->blocked_syscall);
}

STATIC void SYSCALL_SLEEP_ON(monitor_state * this_monitor)
{
    if (this_monitor->syscall_blocked == TRUE)
        PERROR("wierd, looks like process blocked twice");

    this_monitor->syscall_blocked = TRUE;

    PDEBUG("%d sleeping on",current->pid);
    SLEEP_ON_DEEP(&this_monitor->blocked_syscall);
    this_monitor->syscall_blocked = FALSE;

    PDEBUG("%d woke up", current->pid);
}


/* make the newly created child of a process unrunnable */

STATIC struct task_struct * lock_child()
{
    struct task_struct *cp = current->p_cptr;
    
    if (cp) 
        stop_task(cp);
    
    return cp;
}

STATIC void unlock_child(struct task_struct * cp)
{
    if (cp) {
        kassert(current->p_cptr == cp);
        restart_task(cp);
    }
    
}


//globals 

struct {
    int major;
} dev_state;

/* The list of active monitors.  Invariant: all active monitors are attached. */
struct {
    size_t size;
    monitor_state *data[MAX_MONITORS];
} monitor_list = { 0,};

/**** system call replacement **********/


int (*original_sys_call_table[NR_syscalls]) (struct pt_regs);    //saved vectors

extern void *sys_call_table[];    //real vectors

STATIC void set_trap(int call_num)
{
    sys_call_table[call_num] = (void *) syscall_redirect;
}

STATIC void clear_trap(int call_num)
{
}

// init saved table 
STATIC void save_call_table()
{
    memcpy(original_sys_call_table, sys_call_table, 
        NR_syscalls * sizeof(void *));
}

STATIC void restore_call_table()
{
    int i;

    for (i = 0; i < NR_syscalls; i++) {
        if ((sys_call_table[i] != syscall_redirect) &&
            (sys_call_table[i] != original_sys_call_table[i])) {
           PMSG(KERN_EMERG, "System call table corrupted!!");
        } else
            sys_call_table[i] = original_sys_call_table[i];
    }
            
}


STATIC void install_traps(monitor_state * mptr)
{
    int i;

    set_trap(SYS_ptrace);

    for (i = 0; i < NR_syscalls; i++)
        if (TRAP_ISSET(i, &mptr->enter_traps) ||
            TRAP_ISSET(i, &mptr->exit_traps)) 
                set_trap(i);
}

STATIC void remove_traps(monitor_state * mptr)
{
    int i;

    for (i = 0; i < NR_syscalls; i++)
        if (TRAP_ISSET(i, &mptr->enter_traps) ||
            TRAP_ISSET(i, &mptr->exit_traps)) 
            clear_trap(i);

}

//return monitor watching 
STATIC monitor_state *get_monitor_by_pid(pid_t this_pid)
{
    int i;

    for (i = 0; i < monitor_list.size; i++)
        if (monitor_list.data[i]->pid == this_pid)
            return monitor_list.data[i];

    return NULL;
}



//manipulate active list, note that the sanity
//checks that are preformed here need to all
//be done with non-blocking operations
STATIC int activate_monitor(monitor_state * mptr,struct bind_args new_bind)
{
    struct task_struct * tp;
    int err = 0;
   
     
    if ((tp = fetch_task_by_pid(new_bind.pid)) == NULL) {
           PERROR("tried to bind nonexistent process");
           err = -ESRCH;
           goto exit;
    } 
     //perform all sanity checks then activate monitor
    if (mptr->attached == TRUE) {
        PERROR("tried to double bind");
        err = -EBADR;
        goto exit;
    }
         
    //check if process is being ptraced
    if (tp->flags & PF_PTRACED) {
        PERROR("Tried to bind traced process.");
        err = -EBUSY;
        goto exit;
    } 

    if(get_monitor_by_pid(new_bind.pid)) {
        PERROR("tried to bind already monitored process!!");
        err =  -EDEADLK;
        goto exit;
    }

    if (current == tp) {
        PERROR("Process tried to bind itself.");
        err =  -EPERM;
        goto exit;
    }
/*
     if (!tp->dumpable)PDEBUG("");
      if   (current->uid != tp->euid)PDEBUG("");
       if  (current->uid != tp->suid)PDEBUG("");
       if  (current->uid != tp->uid) PDEBUG("");
        if (current->gid != tp->egid)PDEBUG("");
       if  (current->gid != tp->sgid)PDEBUG("");
        if (!cap_issubset(tp->cap_permitted, current->cap_permitted)) PDEBUG("");
        if ((current->gid != tp->gid) && !capable(CAP_SYS_PTRACE)) PDEBUG("");
 */     
    //permission check borrowed from ptrace.c
    if ((!tp->dumpable ||
        (current->uid != tp->euid) ||
        (current->uid != tp->suid) ||
        (current->uid != tp->uid)  ||
        (current->gid != tp->egid) ||
        (current->gid != tp->sgid) ||
        
        /* (!cap_issubset(tp->cap_permitted, current->cap_permitted)) || */
        (current->gid != tp->gid)) && !capable(CAP_SYS_PTRACE)) {
            err = -EACCES; 
            PERROR("permission check failed!");
            goto exit;
    }

    mptr->pid = new_bind.pid;
    mptr->attached = TRUE;
    mptr->enter_traps = new_bind.enter_traps;
    mptr->exit_traps = new_bind.exit_traps;

    install_traps(mptr);
    
    //note this should never happen

    if (monitor_list.size == MAX_MONITORS) {
        PMSG(KERN_CRIT,"mod_janus critical error, monitor list full");
        return -ENOSPC;
    }

    monitor_list.data[monitor_list.size++] = mptr;
    
exit:
    return err;

}


STATIC void deactivate_monitor(monitor_state * mptr)
{
    int i;
    monitor_state *tptr;

    if (monitor_list.size == 0) {
        PERROR("tried to remove nonexistent monitor");
        return;
    }
    //remove from active list
    for (i = 0; (i < monitor_list.size) &&
         (monitor_list.data[i] != mptr); i++);

    monitor_list.size--;

    tptr = monitor_list.data[monitor_list.size];
    monitor_list.data[monitor_list.size] = monitor_list.data[i];
    monitor_list.data[i] = tptr;

}


/******* monitors */

/*update monitor to reflect if an event occured in the monitored process */
STATIC void check_for_death(monitor_state * this_monitor)
{
    struct task_struct *watched_task;

    /* PDEBUG("update monitor called"); */

    watched_task = fetch_task_by_pid(this_monitor->pid);

    if (watched_task == NULL)
        PERROR("proc not found");

    if ((watched_task == NULL) ||
        ((watched_task->state == TASK_STOPPED) && watched_task->exit_code)
        || (watched_task->state == TASK_ZOMBIE)) {

        SET_EVENT_PENDING(this_monitor);
        this_monitor->pending_request.event_type = EVENT_PROC_DIED;
        this_monitor->pending_request.return_value = 0;
        memset(&(this_monitor->pending_request.regs), 0,
              sizeof(this_monitor->pending_request.regs));

        PDEBUG("it appears that %d died", this_monitor->pid);
    }

    /* PDEBUG("update monitor finished"); */
}


STATIC void init_monitor(monitor_state * this_monitor)
{
    this_monitor->pid = UNINITIALIZED;
    this_monitor->attached = FALSE;
    this_monitor->syscall_blocked = FALSE;
    this_monitor->event_pending = FALSE;
    this_monitor->proc_exited = FALSE;
    this_monitor->next_action = UNINITIALIZED;
    this_monitor->blocked_syscall = NULL;
    this_monitor->blocked_read = NULL;
    init_arg_lock(&this_monitor->lock);
}

STATIC void free_monitor(monitor_state * this_monitor)
{

    remove_traps(this_monitor);
    deactivate_monitor(this_monitor);
    vfree(this_monitor);
}


//sleeping and waking up


#define ALLOW_EVENT 0
#define DENY_EVENT 1

/* request_event() could block.
   (Consequently, the monitor could disappear while we block.
   If this happens, we promise to return DENY_EVENT.
   (This saves us from having to check for this case in many places.)) */

STATIC int request_event(monitor_state * this_monitor,
                         struct pt_regs * regs, int * ret_val, int event_type)
{
     //What do we need to ask janus about this event?

    if (event_type == EVENT_CALL_ENTER) {
        if (!TRAP_ISSET(CALL_NUM((*regs)), &this_monitor->enter_traps))
            return ALLOW_EVENT;
    } else if (event_type == EVENT_CALL_EXIT) {
        if (!TRAP_ISSET(CALL_NUM((*regs)), &this_monitor->exit_traps))
            return ALLOW_EVENT;
    }

    //create request

    /* this_monitor->pending_request.pid = this_monitor->pid; */
    this_monitor->pending_request.return_value = *ret_val;
    this_monitor->pending_request.event_type = event_type;
    this_monitor->pending_request.regs = *regs;


    PDEBUG(" %d >> requesting event <%s,%s>",
           current->pid,
           EVENT_STR(this_monitor->pending_request.event_type),
           CALL_STR(CALL_NUM(this_monitor->pending_request.regs)));

    //go to sleep 

    SET_EVENT_PENDING(this_monitor);
    READ_WAKE_UP(this_monitor);
    SYSCALL_SLEEP_ON(this_monitor);
    
    PDEBUG("woke up");

    /* make sure our monitor didn't disappear during the night */
    this_monitor = get_monitor_by_pid(current->pid);


    //ALLOW CALL
    if (this_monitor && (this_monitor->next_action == CALL_ALLOW)) {
        PDEBUG("CALL_ALLOWED");
        return ALLOW_EVENT;
    }
    

    //DENY CALL
    if (this_monitor == NULL) {
        PDEBUG("lost monitor for %d", current->pid);

    } else if (this_monitor->next_action == CALL_DENY) {
        PDEBUG("call %d from %d CALL_DENIED", CALL_NUM(*regs), current->pid);

    } else if (this_monitor->next_action == KILL_PROC) {
        PDEBUG("killing %d", current->pid);
        force_sig(SIGKILL, current);
        free_monitor(this_monitor);
        PDEBUG("monitor free");

    } else 
        PERROR("MASSIVE bogosity bad next action");


    return DENY_EVENT;
}

//called by entry to figure out if a process should be trapped
//if it should return 0 otherwise return the next system call
//to do

#include "fcap_asm.h"

asmlinkage int fcap_is_monitored(int ret,struct pt_regs regs)
{
    monitor_state * mp = get_monitor_by_pid(current->pid);
    
    /* no making ptrace calls on monitored processes! */
    if ((CALL_NUM(regs) == SYS_ptrace) &&
        get_monitor_by_pid(regs.ecx))
        return ILLEGAL_PTRACE;

    //trap trapped calls of monitored processes and ptrace
    if (mp && (TRAP_ISSET(CALL_NUM(regs), &mp->enter_traps) ||
                TRAP_ISSET(CALL_NUM(regs), &mp->exit_traps))) {
        return 0;
    } else {
        return regs.eax;
    }

}

/* if called with call instead of jmp */
/* STATIC asmlinkage int fcap_check_call(int left_as_an_exercise_to_the_reader */
    /* ,struct pt_regs regs) */

STATIC asmlinkage int fcap_check_call(struct pt_regs regs)
{
    monitor_state *this_monitor;
    int next_action = ALLOW_EVENT;
    int call_ret = -EPERM;

    this_monitor = get_monitor_by_pid(current->pid);

    if (this_monitor == NULL) {
        PERROR("trapped a call with no monitor!!, killing %d",current->pid);
        force_sig(SIGKILL,current);
        goto exit_syscall;
    }

    if(lock_args(&this_monitor->lock,&regs))
        goto exit_syscall;

    next_action =
        request_event(this_monitor, &regs, &call_ret, EVENT_CALL_ENTER);

    if (next_action == DENY_EVENT) 
        goto exit_syscall;
    
    /* Do system call */
    if (CALL_NUM(regs) != SYS_execve) { 
        call_ret = (*original_sys_call_table[CALL_NUM(regs)]) (regs);
    } else {
        // do exec inline since it modifies pt_regs
        int size;
        char *filename;
        
        if (this_monitor != NULL) //argument must be locked
           filename = get_locked_arg(&this_monitor->lock,0,&size,TYPE_PATH); 
        else 
           filename = getname((char *) regs.ebx);

        call_ret = PTR_ERR(filename);    // is our file kosher

        if (IS_ERR(filename)) {
            /* DAW: Shouldn't we putname(filename) if this_monitor==NULL? */
            goto exit_syscall;
        } else {
            call_ret = do_execve(filename,
                        (char **) regs.ecx, (char **) regs.edx, &regs);

            //only free this if it is not locked
            if (this_monitor == NULL)
                putname(filename);
        } 
    }

    /* Check Exit */
    
    //the last request_event may have blocked, 
    //as may the last syscall, make sure this_monitor is still valid

    this_monitor = get_monitor_by_pid(current->pid);
    
    /* if we still have a monitor check exit */

    if (this_monitor) {
        struct task_struct * cp = NULL;

        //enforce strict order on fork
        if (CALL_NUM(regs) == __NR_fork)
            cp = lock_child();

        next_action =
            request_event(this_monitor, &regs, &call_ret, EVENT_CALL_EXIT);

        if (next_action == DENY_EVENT)
            call_ret = -EPERM;
       
        //allow child to go ahead only if fork exit is allowed, 
        //otherwise kill it.
        if (CALL_NUM(regs) == __NR_fork) {
                if (next_action != ALLOW_EVENT) {
                    if (cp)
                        force_sig(SIGKILL,cp);
                }

                unlock_child(cp);
        } 
    }


    exit_syscall:

    this_monitor = get_monitor_by_pid(current->pid);

    if (this_monitor != NULL)
        unlock_args(&this_monitor->lock);

    return call_ret;
}

#define CHECK_COPY(x) do {\
    if (x) { PERROR("copy to/from error in: %s.",__FUNCTION__); return x; }\
    if (recieved_signal_p()) return -ERESTARTSYS; \
} while(0)


STATIC ssize_t fcap_write(struct file * filep, const char *input_buff,
                          size_t input_len, loff_t * offset)
{
    int err;
    monitor_state *this_monitor = filep->private_data;
    struct action_args temp_action;

    PDEBUG("write called on %d",this_monitor->pid);
    
    err = copy_from_user(&temp_action, input_buff,
        sizeof(struct action_args));

    CHECK_COPY(err);
    
    if (this_monitor->attached == FALSE) 
        return -EPERM;
    else if (this_monitor->proc_exited == TRUE) 
        return -ESRCH;
    else if (this_monitor->syscall_blocked == FALSE) 
        return -EWOULDBLOCK;
    else if (!VALID_ACTION_P(temp_action.action)) 
        return -EBADRQC;

    this_monitor->next_action = temp_action.action;

    PDEBUG("process %d told to perform %d", this_monitor->pid,
           this_monitor->next_action);

    SYSCALL_WAKE_UP(this_monitor);

    return sizeof(struct action_args);

}

/*** read and poll, wait for watched process to change state */

/* read an event that has occured, note non-blocking read only */

STATIC ssize_t fcap_read(struct file *filep, char *output_buff,
                         size_t length, loff_t * offset)
{
    request_t call_request;        
    monitor_state *this_monitor = filep->private_data;
    int err;

    PDEBUG("read called");

    if (length != sizeof(request_t)) {
        PERROR("invalid read on fcap");
        return -EINVAL;
    } else if (this_monitor->attached != TRUE) {
        PERROR("attempted read on unattached monitor");
        return -EPERM;
    }

    check_for_death(this_monitor);    /* check for death */

    if (EVENT_PENDING_P(this_monitor)) {
        this_monitor->pending_request.pid = this_monitor->pid;
        call_request = this_monitor->pending_request;

        err = copy_to_user(output_buff, &call_request, sizeof(request_t));
        CHECK_COPY(err);
        
        CLEAR_EVENT_PENDING(this_monitor);
        return sizeof(request_t);
    }
    
    //hmmm...nothing pending.
    return -EWOULDBLOCK;

}

STATIC unsigned int fcap_poll(struct file *filep, poll_table * wait_table)
{
    monitor_state *this_monitor = filep->private_data;
    struct task_struct *watched_task;
    
    unsigned int mask = 0;

    if (this_monitor->attached != TRUE) {
        PERROR("attempted poll on unattached monitor");
        return -EPERM;
    }

    check_for_death(this_monitor);    /*see if someone died */
    
    //check if process is already toast 
    if ((watched_task = fetch_task_by_pid(this_monitor->pid)) == NULL)
        goto return_state;

    poll_wait(filep, &this_monitor->blocked_read, wait_table);
    poll_wait(filep, &watched_task->p_pptr->wait_chldexit, wait_table);

    check_for_death(this_monitor);    /*see if someone died */


  return_state: 
    /* say if something happened */

    if (EVENT_PENDING_P(this_monitor)) {
        PDEBUG("poll found syscall blocked = %d",
               this_monitor->syscall_blocked);
        mask |= (POLLIN | POLLRDNORM);
    }

    return mask;
}


#define FETCH_TASK(x) do {\
    if (this_monitor->attached == FALSE) {\
            PERROR("attempted fetchmeta unattached monitor");\
            return -EPERM;\
    } else if ((x = fetch_task_by_pid(this_monitor->pid)) == NULL) {\
        PERROR("Tried to get metadata from dead process");\
        return -ESRCH;\
    } \
} while(0)

STATIC int fcap_ioctl(struct inode *inode, struct file *filep,
                      unsigned int cmd, unsigned long arg)
{
    int err;
    monitor_state *this_monitor = filep->private_data;
    void *in_buff = (void *) arg;

    switch (cmd) {

    case FC_IOCTL_BIND:{
        struct bind_args new_bind;

        err = copy_from_user(&new_bind, in_buff, sizeof(struct bind_args));
        CHECK_COPY(err);

        //trapping these calls is verboten right now
        //as they modify pt_regs, they don't seem
        //to be terribly useful from a security standpoint 
        //anyway. 
        if (TRAP_ISSET(SYS_sigreturn,&new_bind.enter_traps) ||
             TRAP_ISSET(SYS_sigreturn,&new_bind.exit_traps) ||
             TRAP_ISSET(SYS_rt_sigsuspend,&new_bind.enter_traps) ||
             TRAP_ISSET(SYS_rt_sigsuspend,&new_bind.exit_traps)) {
            PERROR("invalid call trap set");
            return -EBADSLT;
        }
        
        err = activate_monitor(this_monitor,new_bind);
        
        if (err) 
            return err;
        
        PDEBUG("now watching %u", this_monitor->pid);

    }
    break;


    case FC_IOCTL_FETCH_ARG: {
        struct fetch_arg_args args;
        unsigned char * buff;
        int size; 

        err = copy_from_user(&args, in_buff, sizeof(struct fetch_arg_args));
        CHECK_COPY(err);

        if (this_monitor->attached == FALSE) {
            PERROR("attempted fetch arg on unattached mon");
            return -EPERM;
        }

        buff = get_locked_arg(&this_monitor->lock,args.arg,&size,args.type);

        if (args.size < size) {
            PERROR("wrong size arg %d < %d ",args.size,size);
            return -EINVAL;
        }

        if (buff != NULL) {
            err = copy_to_user(args.dest,buff,size);
            CHECK_COPY(err);
        } else {
            PERROR("tried to fetch bad arg");
            return -ENODATA;
        }

    }
    break;

    case FC_IOCTL_FETCH_META: {
        struct fetchmeta_args args;
        struct task_struct * tp;

        err = copy_from_user(&args, in_buff, sizeof(struct fetchmeta_args));
        CHECK_COPY(err);        
 
        if (args.type == FCAP_SOCK_INFO) {
            int sd;
            int serror;
            struct fcap_socket_info sinfo;
            struct socket * sp;
            
            err = copy_from_user(&sd, args.arg, sizeof(int));
            CHECK_COPY(err); 
             
            PDEBUG("requested sockinfo");
            
            FETCH_TASK(tp);
            sp = lookup_socket(tp,sd,&serror);

            if (sp == NULL) {
                PERROR("Error looking up socket");     
                return -EBADR;
            }

            sinfo.type = sp->type;

            if (args.size < sizeof(struct fcap_socket_info)) {
                PERROR("invalid size to fetchmeta");
                return -EINVAL;
            }
                
            err = copy_to_user(args.dest,
                   &sinfo,sizeof(struct fcap_socket_info));
            
            CHECK_COPY(err);

        } else if (args.type ==  FCAP_FD_INFO) {
            int fd;
            int ferror;
            struct file * fp;
            struct fcap_fd_info finfo;
            
            err = copy_from_user(&fd, args.arg, sizeof(int));
            CHECK_COPY(err);    

            PDEBUG("requested sockinfo");
            FETCH_TASK(tp); 
            fp = get_file(tp,fd,&ferror);

            if (fp == NULL) {
                PERROR("Error looking up file");     
                return -EBADR;
            }

            finfo.flags = fp->f_flags;

            if (args.size < sizeof(struct fcap_fd_info)) {
                PERROR("invalid size to fetchmeta");
                return -EINVAL;
            }
                
            err = copy_to_user(args.dest, &finfo,sizeof(struct fcap_fd_info));
            CHECK_COPY(err);

        } else {
            PERROR("invalid type to fetchmeta");
            return -EBADRQC;
        }


    };
    break;
        default:
        PERROR("invalid arg to ioctl");
        return -EINVAL;
        break;
    }

    return 0;
}


/* intialization, setup and cleanup */

STATIC int fcap_open(struct inode *inode, struct file *filep);
STATIC int fcap_close(struct inode *inode, struct file *filep);


struct file_operations fcap_file_operations = {
    NULL,                        /* lseek */
    fcap_read,                    /* "read" from the file */
    fcap_write,                    /* "write" to the file */
    NULL,                        /* readdir */
    fcap_poll,                    /* poll */
    fcap_ioctl,                    /* ioctl */
    NULL,                        /* mmap */
    fcap_open,
    NULL,
    fcap_close,                    /*release */

    /*leave the rest null */

};


STATIC int fcap_open(struct inode *inode, struct file *filep)
{
    monitor_state *new_mon;

    PDEBUG("fcap opened by process %i", current->pid);

    if (GLOBAL_USE_COUNT() >= MAX_MONITORS) {
        PERROR("tried to excede number of monitors limit");
        return -ENOSPC;
    } 

    new_mon = vmalloc(sizeof(monitor_state));

    if (new_mon == NULL) {
        PERROR("Insufficient memory for new monitor");
        return -ENOMEM;
    }

    
    init_monitor(new_mon);

    filep->private_data = new_mon;

    ADD_USE_COUNT();

    return 0;
}

STATIC int fcap_close(struct inode *inode, struct file *filep)
{
    monitor_state *this_monitor = filep->private_data;
    struct task_struct *tp;
    
    if (!this_monitor->attached) {
       PDEBUG("Closing unattached monitor.");
       vfree(this_monitor);
    } else {
        
        //note that this difference in dealing
        //with blocked processes vs. no blocked
        //processes is important. 
        
        //a blocked process(one which is blocked 
        //in request_event is blocked
        //on a waitqueue that is part of the
        //monitor so we cannot free the
        //monitor 'till it wakes up.
        struct siginfo info;

        memset(&info, 0, sizeof(info));
        
        info.si_signo = SIGKILL;
        info.si_errno = 0;
        info.si_code = SI_USER;
        info.si_pid = current->pid;
        info.si_uid = current->uid;

        tp = fetch_task_by_pid(this_monitor->pid);
        
        //process looks already dead, make sure
        //this is the case then cleanup
        //admittedly a bit redundant
        if (!tp && !this_monitor->syscall_blocked) {
            PDEBUG("Closing already dead process: %d",this_monitor->pid);
            this_monitor->next_action = KILL_PROC; 
            kill_proc_info(SIGKILL, &info, this_monitor->pid);
            free_monitor(this_monitor);
        //monitor is sleeping on a dynamically allocated waitque,
        //let it kill then free itself.
        } else if (this_monitor->syscall_blocked) {
            PDEBUG("Closing blocked process: %d",this_monitor->pid);
            this_monitor->next_action = KILL_PROC;
            SYSCALL_WAKE_UP(this_monitor);
        //process is running, just kill it.
        } else {
            PDEBUG("Closing running process: %d",this_monitor->pid);
            force_sig(SIGKILL,tp);
            free_monitor(this_monitor);    
        }
    }

    DEC_USE_COUNT();

    if (!IN_USE_P())
        restore_call_table();

    return 0;
}



/* install and cleanup */
/* [KEN] a "start" (initialization) function 
    Typically, init_module() either registers a handler for something with the kernel, 
    or it replaces one of the kernel functions with its own code (usually code to do 
    something and then call the original function)

    Source: http://www.tldp.org/LDP/lkmpg/2.6/html/lkmpg.html#AEN119
*/
int init_module(void)
{
    int ret;

    /* request a major number dynamically */
    /* [KEN] Register as a character device,
        see: https://www.win.tue.nl/~aeb/linux/lk/lk-11.html  */
    ret = register_chrdev(0, "mod_janus", &fcap_file_operations);

    if (ret < 0) {
        PERROR("error registering device");
        return ret;
    }

    dev_state.major = ret;
    save_call_table();

    PNOTE("installed:%s", __modversion);
    PNOTE("build:%s %s", __DATE__, __TIME__);

    return 0;
}

/* [KEN] "end" function */
int cleanup_module(void)
{
    int ret;

    restore_call_table();
    ret = unregister_chrdev(dev_state.major, "mod_janus");

    if (ret < 0) {
        PERROR("error unregistering device");
        return ret;
    }

    PNOTE("fcap exiting..");

    return 0;
}



