/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* handy module for allowing calls explicity without
the need to code a new module */

#include "module.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sysxlat.h"

static syscall_entry   entries[] = {
    /* XXX: Note: this will be overwritten by init(). */
    {SYS_read, ALLOW, 0},
};


static void *	init(const char *conf_line)
{
    int callnum;

    if (!conf_line) {
        fprintf(stderr, "Usage: force_allow callname\n");
        exit(1);
    }
    
    if ((callnum = xlat_callname(conf_line)) < 0) {
        fprintf(stderr, "Usage: force_allow callname\n");
        fprintf(stderr, "invalid callname %s\n",conf_line);
        exit(1);
    }

    PDEBUG("force_allowing %d (%s)\n", callnum, xlat_callnum(callnum));

    entries[0].which = callnum;

    return 0; 
}

static const int	nentries = sizeof(entries) / sizeof(syscall_entry);

void * force_allow_init(const char * conf) { return init(conf); }
int force_allow_num_entries() { return nentries; }
const syscall_entry * force_allow_get_entries() { return entries; }


