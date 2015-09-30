/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef __MODULE_H__
#define __MODULE_H__

#include <sys/syscall.h>
#include <sys/procfs.h>
#include <linux/sys.h>
#include "trace.h"

#define NSYSCALL NR_syscalls

#define INIT_FAIL ((void *)-1)

typedef enum {
    NO_COMMENT, DENY, ALLOW,
    FUNC, EXIT_FUNC /* for syscall_entry.kind only */
} action;

typedef struct {
    int		which;
    action	kind; /* if kind == FUNC, call hook() below */
    action	(*hook)(const prstat_t *, void *);
} syscall_entry;

/* deny interface:

modules should never call deny directly 
but instead use the idiom, 
return deny(level,message)

*/
#define MAX_DENY_MSG 256

#define DENY_SHUTDOWN 10
#define DENY_KILL   5  
#define DENY_DEFAULT 1  

int deny(int level,char * fmt,...);

/* module interfaces */

void * net_init(const char * conf);
int net_num_entries();
const syscall_entry * net_get_entries();

void * path_init(const char * conf);
int path_num_entries();
const syscall_entry * path_get_entries();


void * group_init(const char * conf);
int group_num_entries();
const syscall_entry * group_get_entries();
     
void * uid_init(const char * conf);
int uid_num_entries();
const syscall_entry * uid_get_entries();
 
void * force_allow_init(const char * conf);
int force_allow_num_entries();
const syscall_entry * force_allow_get_entries();
   

void * chdir_init(const char * conf);
int chdir_num_entries();
const syscall_entry * chdir_get_entries();

void * basic_init(const char * conf);
int basic_num_entries();
const syscall_entry * basic_get_entries();
 
#endif
