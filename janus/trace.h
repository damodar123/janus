/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef __TRACE_H__
#define __TRACE_H__
#include <sys/types.h>
#include <fcap.h>

typedef trap_set mask_t;

void	addtomask(mask_t *m, int syscallnum);
void    clear_mask(mask_t * m);
void    set_global_mask(mask_t entermask,mask_t exitmask);


typedef struct pcb_struct { /* process control block */
    monitor_t md;   
	pid_t	pid;
	struct pcb_struct *next;
} pcb_t;

pcb_t * pid2pcb(pid_t);
int	   pcbsinuse(void);
void   release_pcb(pcb_t *);


typedef struct {
	pcb_t	*pcb;
	enum {UNKNOWN, SYSENTRY, SYSEXIT, PROCESSEXIT} why;
	int	syscall;
	int	rv;
	unsigned long args[5];
    int pid;
} prstat_t;

int     attach(pid_t pid);
void	slay(pcb_t *);

int	runtraced(pcb_t *, int abortp);

/* Block and wait for an event.
   Fills in some fields the 'pr' structure; which fields depends on pr->why.
   Here's the breakdown of which fields will be set, for each pr->why:
     SYSENTRY => pcb, syscall, args
     SYSEXIT => pcb, syscall, rv (but NOT args!)
     UNKNOWN, PROCESSEXIT => nothing (ALL are uninitialized!)
   The caller must not use any uninitialized field. */
int	waitevent(prstat_t *pr);

int fetcharg(const pcb_t *, int arg,void * dest,int size,int type);

int fetch_sockettype(pcb_t * p,int fd,int * type);
int fetch_fd_flags(pcb_t * p, int fd, int * flags);

#endif
