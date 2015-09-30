
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef LOCK_H
#define LOCK_H

#include <asm/uaccess.h>  //memory segment stuff       
#include <asm/page.h>     //page sizes
#include "modtools.h"

#define MAX_SOCK_ADDR	128	
#define MAX_ARGS 6


typedef struct __arglock_t {
    int lock_set;
    mm_segment_t userfs;            //user segment

    int type[MAX_ARGS];  //is this a pointer or scalar?
    unsigned long argv[MAX_ARGS]; //argument
    int size[MAX_ARGS];   //size
    mybool locked[MAX_ARGS];        //is there something here

    unsigned long sockarg_a[MAX_ARGS][MAX_SOCK_ADDR];  //space for non-scalar socket args

    //space for pathnames
    unsigned char path_a[MAX_ARGS][PAGE_SIZE];
    unsigned char path_follow[MAX_ARGS][PAGE_SIZE];
    unsigned char path_nofollow[MAX_ARGS][PAGE_SIZE];

} arglock_t ;


void init_arg_lock(arglock_t * lp);

unsigned char * get_locked_arg(const arglock_t * lp,int arg,int * size,int type);

int lock_args(arglock_t * lp, struct pt_regs * regs);
void unlock_args(arglock_t * lp);

#endif
