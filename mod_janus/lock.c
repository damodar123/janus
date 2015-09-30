
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* some routines for messing with memory some code based on ptrace.c*/

#define __NO_VERSION__

#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>        /*helpful string and mem ops */
#include <linux/socket.h>
#include <linux/fs.h>
#include <linux/utime.h>
#include <linux/mm.h>

#include <asm/uaccess.h>

#include <sys/syscall.h>        /* system call #s */
#include "lock.h"
#include "modtools.h"
#include "callnames.h"
#include "fcap.h"

#define CALL_NUM(regs) ((regs).eax)       

#define STATIC 

//stuff with only a single path name in its arguments

#define SINGLE_PATHNAME_P(x)( ((x) == SYS_open)   || \
                              ((x) == SYS_creat)  || \
                              ((x) == SYS_rmdir)  || \
                              ((x) == SYS_mkdir)  || \
                              ((x) == SYS_chdir)  || \
                              ((x) == SYS_mknod)  || \
                              ((x) == SYS_chroot) || \
                              ((x) == SYS_lchown) || \
                              ((x) == SYS_umount) || \
                              ((x) == SYS_umount2) ||\
                              ((x) == SYS_chown) || \
                              ((x) == SYS_chmod) || \
                              ((x) == SYS_unlink) || \
                              ((x) == SYS_access) )

//stuff with two path names as arguments
#define DOUBLE_PATHNAME_P(x)( ((x) == SYS_link) || \
                              ((x) == SYS_symlink) ||\
                              ((x) == SYS_rename) )

//stat stuff
#define STAT_CALL_P(x) ( ((x) == SYS_stat) || \
                         ((x) == SYS_lstat) || \
                         ((x) == SYS_statfs))

void init_arg_lock(arglock_t * lp)
{
    int i;
    
    lp->lock_set = FALSE;
    lp->userfs = KERNEL_DS;

    for (i = 0; i < MAX_ARGS; i++) {
        lp->argv[i] = 0;
        lp->locked[i] = FALSE;
    }
}


//Ack!! we have to do some icky stuff with size here
//this functions interface really sucks, it should return an error code
//and be passed a * * arg.
unsigned char * get_locked_arg(const arglock_t * lp,int arg,int * size,int type)
{

    if (!lp->lock_set || !lp->locked[arg])
        return NULL;
        
    if ((type == TYPE_SCALAR) && (lp->type[arg] == TYPE_SCALAR)) {
        *size = lp->size[arg];
        return  (unsigned char *)&lp->argv[arg];
    }
    
    if ((type == TYPE_PATH) && (lp->type[arg] == TYPE_PATH)) {
        *size = strlen(lp->path_a[arg]) + 1;
        return  (unsigned char *)lp->path_a[arg];
    }

    if ((type == TYPE_PATH_NOFOLLOW) && (lp->type[arg] == TYPE_PATH)) {
        *size = strlen(lp->path_nofollow[arg]) + 1;
        return  (unsigned char *)lp->path_nofollow[arg];
    }
    
    if ((type == TYPE_PATH_FOLLOW) && (lp->type[arg] == TYPE_PATH)) {
        *size = strlen(lp->path_follow[arg]) + 1;
        return  (unsigned char *)lp->path_follow[arg];
    }
   
    //note this is a little filthy.
    if ((type == TYPE_POINTER) && (lp->type[arg] == TYPE_POINTER)) {
        *size = lp->size[arg];
        return (unsigned char *)lp->argv[arg];
    }
    
    if ((type == TYPE_SOCKADDR) && (lp->type[arg] == TYPE_SOCKADDR)) {
        *size = lp->size[arg];
        return (unsigned char *)lp->sockarg_a[arg];
    }

    return NULL;
    
}


STATIC void disable_checks(arglock_t * lp)
{
    lp->lock_set = TRUE; 
    lp->userfs = get_fs();
    set_fs(KERNEL_DS);
}

STATIC void set_arg_lock(arglock_t * lp,int slot,unsigned long arg,int type, int size)
{
    lp->lock_set = TRUE; 
    lp->argv[slot] = arg;
    lp->size[slot] = size;
    lp->type[slot] = type;
    lp->locked[slot] = TRUE;
}

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static unsigned char socket_nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
				AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
				AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
#undef AL

STATIC int move_addr_to_kernel(void *uaddr, int ulen, void *kaddr)
{
	if(ulen<0||ulen>MAX_SOCK_ADDR)
		return -EINVAL;
	if(ulen==0)
		return 0;
	if(copy_from_user(kaddr,uaddr,ulen))
		return -EFAULT;
	return 0;
}

//copy socketcall arguments to appropriate place 
//munge register

int lock_socket_args(arglock_t * lp, struct pt_regs * regs)
{
    int call = regs->ebx;
    unsigned long args[MAX_ARGS];
    int err;

    //check if we lock this
    if ((call != SYS_BIND) && (call != SYS_CONNECT) &&
        (call != SYS_SOCKET) && (call != SYS_SENDTO) &&
        (call != SYS_SETSOCKOPT))
        return 0;

    if(call<1||call>SYS_RECVMSG) 
		return -EINVAL;
    
    err = copy_from_user(args,(unsigned char *)regs->ecx,socket_nargs[call]);

    if (err) { 
        PERROR("error grabing socket argv"); 
        return err; 
    }
    
    switch(call) {
        case SYS_SOCKET:
            set_arg_lock(lp,0,args[0],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,1,args[1],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,2,args[2],TYPE_SCALAR,sizeof(int));
        break;

        case SYS_CONNECT:
        case SYS_BIND: {

            struct sockaddr * uaddr = (struct sockaddr *) args[1];
            int addrlen = args[2];

            PDEBUG("other %ld %ld %ld",args[0],args[1],args[2]);

            set_arg_lock(lp,0,args[0],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,1,(unsigned long)lp->sockarg_a[1],TYPE_SOCKADDR,addrlen);
            set_arg_lock(lp,2,args[2],TYPE_SCALAR,sizeof(int));

            err = move_addr_to_kernel(uaddr,addrlen,lp->sockarg_a[1]);

            if (err) { PERROR("error grabing sockaddr "); return err; }

        }
        break;
        case SYS_SETSOCKOPT: {
            void * optaddr = (void *) args[3];
            int optlen = args[4]; 
            
            if (optlen > MAX_SOCK_ADDR) {
                PERROR("setsockopt optval size exceeds max size");
                return -EINVAL;
            }

            set_arg_lock(lp,0,args[0],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,1,args[1],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,2,args[2],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,3,(unsigned long)lp->sockarg_a[3],TYPE_SOCKADDR,optlen);
            set_arg_lock(lp,4,args[4],TYPE_SCALAR,sizeof(int));
            
            err = copy_from_user(lp->sockarg_a[3],optaddr,optlen);

            if (err) { PERROR("error grabing optval "); return err; }

        };
        break;

        case SYS_SENDTO: {
            struct sockaddr * uaddr = (struct sockaddr *) args[4];
            int addrlen = args[5];

            if (addrlen > MAX_SOCK_ADDR) {
                PERROR("sendto sockaddr size exceeds max size");
                return -EINVAL;
            }

            set_arg_lock(lp,0,args[0],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,1,args[1],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,2,args[2],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,3,args[3],TYPE_SCALAR,sizeof(int));
            set_arg_lock(lp,4,(unsigned long)lp->sockarg_a[4],TYPE_SOCKADDR,addrlen);
            set_arg_lock(lp,5,args[5],TYPE_SCALAR,sizeof(int));
            
            err = move_addr_to_kernel(uaddr,addrlen,lp->sockarg_a[4]);

            if (err) { PERROR("error grabing sockaddr "); return err; }
        };
        break;

        default: 
            PERROR("invalid socketcall type!!!"); 
            return -EINVAL;
        break;
    }

    PDEBUG("4");
    //assume everything OK!

    regs->ecx = (unsigned long)lp->argv; //munge arg register
    disable_checks(lp);     //remove checks


    return 0;
}

//NOTE!!! unsure if I should be grabing an 
//additional lock here.

// this resolves the given pathname to a symlink free
// absolute path and makes that the new arg.
STATIC int lock_pathname(arglock_t * lp, struct pt_regs * regs, int arg)
{
    char * fname = getname((char *) regs->ebx + arg);
    struct dentry * dent;
    char * no_follow_path,
         * follow_path,  
         *page;
    int err = 0;

    if (IS_ERR(fname))  
        return PTR_ERR(fname); 
    
    page = (char *) __get_free_page(GFP_USER);
    
    if (!page) {
        putname(fname);
        return -ENOMEM;
    }

    //note if the file does not exist we
    //propagate the ENOENT from lookup_dentry back.
    //so this should preserve normal semantics.
    
    //grab path and follow final symlink
    dent = lookup_dentry(fname,NULL,LOOKUP_FOLLOW);
        
    if (IS_ERR(dent)) {
        err = PTR_ERR(dent);
        goto out;
    }

    follow_path = d_path(dent,page,PAGE_SIZE);
    dput(dent);

    if (!follow_path) {    //this is a little fishy from the applications perspective
        err =  -EINVAL;
        goto out;
    }

    strncpy(lp->path_follow[arg],follow_path,PAGE_SIZE);
    lp->path_follow[arg][PAGE_SIZE - 1] = '\0';

    //grab path without final symlink
    dent = lookup_dentry(fname,NULL,0);
        
    if (IS_ERR(dent)) {
        err = PTR_ERR(dent);
        goto out;
    }


    no_follow_path = d_path(dent,page,PAGE_SIZE);
    dput(dent);

    if (!no_follow_path) {
        err = -EINVAL;
        goto out;
    }

    strncpy(lp->path_nofollow[arg],no_follow_path,PAGE_SIZE);
    lp->path_nofollow[arg][PAGE_SIZE - 1] = '\0';

    //lock normal path for systemcall

    strncpy(lp->path_a[arg],fname,PAGE_SIZE);
    lp->path_a[arg][PAGE_SIZE - 1] = '\0';

    set_arg_lock(lp,arg,(unsigned long)lp->path_a[arg],TYPE_PATH,(strlen(fname) + 1) * sizeof(char));

    //modify system call argument
    *(&regs->ebx + arg) = (unsigned long) lp->path_a[arg];
    
    out:
        free_page((unsigned long) page);    
        putname(fname);
        return err;
}

#define CHECK_ERR(x) do { if (x < 0) goto exit_error; } while (0)

int lock_args(arglock_t * lp, struct pt_regs * regs)
{
    int err;

    if (CALL_NUM(*regs) == SYS_socketcall) 
        return lock_socket_args(lp,regs);

    //calls of the form foo(char * path)

    if (SINGLE_PATHNAME_P(CALL_NUM(*regs))) {
        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);

        disable_checks(lp); 
    } else if (DOUBLE_PATHNAME_P(CALL_NUM(*regs))) {
        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);
        
        err = lock_pathname(lp,regs,1);
        CHECK_ERR(err);

        disable_checks(lp); 
    
    //don't need to disable checks as exec is done inline
    }  else if (CALL_NUM(*regs) == SYS_execve) {

        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);


    } else if (CALL_NUM(*regs) == SYS_utime) {


        //check time buff
        err = access_ok(VERIFY_READ, (char *) regs->ecx, sizeof(struct utimbuf));
        CHECK_ERR(err);

        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);

        disable_checks(lp); 
    
    } else if (CALL_NUM(*regs) == SYS_readlink) {


        //check path buff
        err = access_ok(VERIFY_READ, (char *) regs->ecx,regs->edx);
        CHECK_ERR(err);

        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);

        disable_checks(lp); 

    } else if (CALL_NUM(*regs) == SYS_setgroups) {
        int num_groups = (int)regs->ebx;
        int * glist = (int *)regs->ecx;

        if (num_groups > NGROUPS) {
            err = -EINVAL;
            CHECK_ERR(err);
        }
            
        err = copy_from_user(lp->path_a[1],glist,num_groups * sizeof(janus_gid_t));

        CHECK_ERR(err);

        set_arg_lock(lp,1,(unsigned long)lp->path_a[1],TYPE_POINTER,
            num_groups * sizeof(janus_gid_t));

        //munch register
        regs->ecx = (unsigned long)lp->path_a[1];
        disable_checks(lp);

    } else if (STAT_CALL_P(CALL_NUM(*regs))) {

        if (CALL_NUM(*regs) == SYS_statfs)
            err = access_ok(VERIFY_WRITE, (char *) regs->ecx,
                sizeof(struct statfs));
        else 
            err = access_ok(VERIFY_WRITE, (char *) regs->ecx,
                sizeof(struct __old_kernel_stat));
        
        CHECK_ERR(err);

        err = lock_pathname(lp,regs,0);
        CHECK_ERR(err);

        disable_checks(lp);
    }
    
    return 0;

    exit_error:
        return err;
 } 

#undef CHECK_ERR

void unlock_args(arglock_t * lp)
{
    if (lp->lock_set == TRUE) {
        if (!segment_eq(lp->userfs,KERNEL_DS)) //renable argument checking
            set_fs(lp->userfs);
        
        init_arg_lock(lp);    //re-init lock
    }
} 

