
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "fcap.h"
#include "fcap_kernel.h"

/* monitors lead basic lives */

int create_monitor(const char * watch_device)
{
        return open(watch_device,O_RDWR);
}

int destroy_monitor(monitor_t destroy_me)
{
       return close(destroy_me);
}


int bind_monitor(monitor_t this_monitor, unsigned int watch_me, 
trap_set enter_mask,trap_set exit_mask)
{
        struct bind_args args = {enter_mask,exit_mask,watch_me};
        return ioctl(this_monitor,FC_IOCTL_BIND,&args);
}


int read_request(monitor_t wait_on_me, request_t * new_request)
{

       return read(wait_on_me,new_request, sizeof(request_t)); 
}

int action_monitor(monitor_t this_monitor, action_t action)
{
       struct action_args args = {action};
       return write(this_monitor,&args,sizeof(struct action_args));
}

int fcap_fetcharg(monitor_t this_monitor,int arg ,void * dest,int size,int type)
{
        struct fetch_arg_args args = {arg,(unsigned char *)dest,size,type};
        return ioctl(this_monitor,FC_IOCTL_FETCH_ARG,&args);
}

int fcap_fetchmeta(monitor_t this_monitor,int type,void * arg, void * dest,
int size)
{
        struct fetchmeta_args args = {type,(unsigned char *)arg,(unsigned char *)dest,size};
        return ioctl(this_monitor,FC_IOCTL_FETCH_META,&args);
}
