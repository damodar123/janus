
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* this provides a low level interface to fcap, if you are
   using libfcap you need not look at this */


#ifndef FCAP_KERNEL_H
#define FCAP_KERNEL_H

/* the ioctl interface  */
#define FC_IOCTL_BIND 1 
#define FC_IOCTL_NEXT_ACTION 2
#define FC_IOCTL_READ_MEM 3
#define FC_IOCTL_FETCH_ARG 4
#define FC_IOCTL_FETCH_META 5

/* stuff for structuring arguments */

struct bind_args {
       trap_set enter_traps;
       trap_set exit_traps;
       int pid;
};

struct reset_args {
       trap_set enter_traps;
       trap_set exit_traps;
};

struct fetch_arg_args {
    int arg;
    unsigned char * dest;
    int size;
    int type;
};

struct action_args {
       int action;
};

struct fetchmeta_args {
       int type;
       unsigned char * arg;
       unsigned char * dest;
       int size;
};

#endif
