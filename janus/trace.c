/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <linux/sys.h>
#include <unistd.h>
#include "debug.h"
#include "trace.h"
#include "sysxlat.h"

#define FCAP_DEVICE "/dev/mod_janus"

static mask_t global_enter_mask;
static mask_t global_exit_mask;
static int global_masks_initted = 0;

#define REPORT_ERR() PDEBUG("%s failed: %s",__FUNCTION__,strerror(errno))

void set_global_mask(mask_t entermask, mask_t exitmask)
{
    global_enter_mask = entermask;
    global_exit_mask = exitmask;
    global_masks_initted = 1;
}

void clear_mask(mask_t * m)
{
    assert(m);
    TRAP_ZERO(m);
}

void addtomask(mask_t * m, int syscallnum)
{
    assert(m && syscallnum >= 0 && syscallnum < NR_syscalls);
    TRAP_SET(syscallnum, m);
}

static pcb_t *head_pcb = 0;

static pcb_t *mallocpcb(void)
{
    /* linked-list of pcbs, add new one to head, return head
        note that *head_pcb is also global */
    pcb_t *p;

    p = (pcb_t *) malloc(sizeof(pcb_t));
    assert(p != NULL);

    p->next = head_pcb;
    head_pcb = p;

    return p;
}

static void freepcb(pcb_t * p)
{
    pcb_t *q;

    assert(p != NULL);

    if (p == head_pcb) {
        head_pcb = head_pcb->next;
        free(p);
        return;
    }

    for (q = head_pcb; q; q = q->next)
        if (q->next == p) {
            q->next = p->next;
            free(p);
            return;
        }
}

void release_pcb(pcb_t * p)
{
    assert(p != NULL);
    freepcb(p);
}

pcb_t *pid2pcb(pid_t pid)
{
    pcb_t *p;

    for (p = head_pcb; p; p = p->next) {
        if (p->pid == pid)
            return (p);
    }

    return NULL;
}

int pcbsinuse(void)
{
    int i;
    pcb_t *p;

    i = 0;
    for (p = head_pcb; p; p = p->next)
        i++;

    PDEBUG("inuse %d", i);

    return i;
}

void slay(pcb_t * p)
{
    assert(p);
    destroy_monitor(p->md);
    ASSERT(p->pid);         //Why is this here?
}


//create a new monitor and bind it to a process
int attach(pid_t pid)
{
    int err;
    monitor_t md;
    pcb_t *p;
    
    //make sure we are not already tracing this process
    assert(!pid2pcb(pid));

    /* Defined in fcap.h, library for mod_janus
        FCAP_DEVICE is /dev/mod_janus
        open syscall is made, returns a file descriptor
    */
    md = create_monitor(FCAP_DEVICE);

    /* md < 0 -> error on open syscall */
    if (md < 0) {
        PERROR("Error: \"%s\", unable to open %s.",strerror(errno),FCAP_DEVICE);
        PERROR("Did you remember to load %s?", FCAP_DEVICE);
        PERROR("(If not, see the INSTALL instructions.)");
        exit(1);
    }

    //presumably our trapsets are setup
    assert(global_masks_initted);

    /* {global_enter_mask, global_exit_mask, pid} passed to ioctl as args 
        in bind_monitor. ioctl is used to monitor process
        From paper:
        /proc uses ioctls on a special file under the /proc filelesystem: the tracer 
        issues an ioctl that blocks until a tracing event is available at the tracee. 
        TODO: Investigate HOW ioctl is used to monitor processes */
    err = bind_monitor(md, pid, global_enter_mask, global_exit_mask);

    if (err < 0) REPORT_ERR();
    assert(err >= 0);

    PDEBUG("attaching to %d", pid);

    p = mallocpcb();

    ASSERT(p != NULL);

    p->pid = pid;
    p->md = md;

    return 0;
}



int runtraced(pcb_t * p, int abortp)
{
    int err;

    assert(p);

    if (abortp)
        err = action_monitor(p->md, CALL_DENY);
    else 
        err = action_monitor(p->md, CALL_ALLOW);

    if (err < 0) REPORT_ERR();
    assert(err >= 0);

    return 0;
}


#define ARG0    regs.ebx
#define ARG1    regs.ecx
#define ARG2    regs.edx
#define ARG3    regs.esi
#define ARG4    regs.edi


static void request_to_prstat(request_t * new_request,
                              prstat_t * new_event)

{
    pcb_t *p;

    assert(new_request);
    p = pid2pcb(new_request->pid);
    assert(p != NULL);
    bzero(new_event,sizeof(prstat_t));

    new_event->pcb = p;
    new_event->syscall = CALL_NUM(new_request->regs);

    /* XXX: Should maybe initialize all fields of new_event to
       something innocuous, in case they don't get set? */

    new_event->pid = new_request->pid;

    switch (new_request->event_type) {
    case EVENT_CALL_EXIT:
        new_event->why = SYSEXIT;
        new_event->rv = new_request->return_value;
        break;
    case EVENT_CALL_ENTER:
        new_event->why = SYSENTRY;
        new_event->args[0] = new_request->ARG0;
        new_event->args[1] = new_request->ARG1;
        new_event->args[2] = new_request->ARG2;
        new_event->args[3] = new_request->ARG3;
        new_event->args[4] = new_request->ARG4;
        break;
    case EVENT_PROC_DIED:
        PDEBUG("processes died");
        new_event->why = PROCESSEXIT;
        PDEBUG("PROCESSEXIT pid %d", new_event->pcb->pid);
        destroy_monitor(new_event->pcb->md);
        freepcb(new_event->pcb);
        new_event->pcb = NULL;
        break;
    default:
        PDEBUG("Unexpected event type (%d)\n", new_request->event_type);
        assert(0);
    }
}

/* Zero out the structure, so we don't leak any old information */
static void zero_prstat(prstat_t *pr)
{
    assert(pr);
    pr->pcb = NULL;
    pr->why = UNKNOWN;
    pr->syscall = 0;
    pr->rv = 0;
    pr->args[0] = 0;
    pr->args[1] = 0;
    pr->args[2] = 0;
    pr->args[3] = 0;
    pr->args[4] = 0;
}

#define MAX(x,y) ((x) > (y) ? (x) : (y))

int waitevent(prstat_t * new_event)
{
    pcb_t *p;
    fd_set watch_set;
    int max_fd = 0;
    int ret;
    int i;
    request_t new_request;

    assert(new_event != NULL);

    FD_ZERO(&watch_set);

    for (p = head_pcb; p; p = p->next) {
        FD_SET(p->md, &watch_set);
        max_fd = MAX(max_fd, p->md);
    }

    get_event: 
    ret = select(max_fd + 1, &watch_set, NULL, NULL, NULL);

    if ((ret <= 0) && (errno == EINTR))
        goto get_event;

    if (ret <= 0) REPORT_ERR();
    assert(ret > 0);

    for (i = 0; (i < max_fd + 1) && !FD_ISSET(i, &watch_set); i++)
        ;
    ASSERT(i != (max_fd + 1));

    /* Reads requests sent to monitoring device */
    ret = read_request(i, &new_request);

    if (ret != sizeof(request_t))
        REPORT_ERR();

    assert(ret == sizeof(request_t));

    zero_prstat(new_event);
    request_to_prstat(&new_request, new_event);

    return 0;
}

int fetcharg(const pcb_t * p, int arg, void *dest, int size,int type)
{
    int err;
    
    assert(p && dest && size >= 0);
    err = fcap_fetcharg(p->md, arg, dest, size, type);
    return err;
}

int fetch_sockettype(pcb_t * p, int fd, int *type)
{
	struct fcap_socket_info si;
	int err;

    assert(p && type);
    err = fcap_fetchmeta(p->md, FCAP_SOCK_INFO,
                         (unsigned char *) &fd,
                         (unsigned char *) &si,
                         sizeof(struct fcap_socket_info));
    if (err) REPORT_ERR();
    assert(!err);

    *type = si.type;

    PDEBUG("socket type %s", xlat_socket_type(*type));

    return 0;
}

int fetch_fd_flags(pcb_t * p, int fd, int * flags)
{
	struct fcap_fd_info fi;
	int err;

    assert(p && flags);
    err = fcap_fetchmeta(p->md, FCAP_FD_INFO,
                         (unsigned char *) &fd,
                         (unsigned char *) &fi,
                         sizeof(struct fcap_fd_info));
    assert(!err);

    *flags = fi.flags;

    PDEBUG("file flags %d", *flags);

    return 0;
}


