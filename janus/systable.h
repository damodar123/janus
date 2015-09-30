/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef __SYSTABLE_H__
#define __SYSTABLE_H__

#include <stdio.h>
#include "trace.h"
#include "module.h"

typedef struct s_actionnode {
    action kind;
    action (*hook)(const prstat_t *, void *);
    void *state;
    struct s_actionnode *next;
} actionnode;

typedef struct s_actionlist {
    actionnode *head;
    actionnode **tail;
} actionlist;

/* The action table is an array, indexed by syscall number, of actionlists. */

void init_table(actionlist[]);
void conf_table(FILE *, actionlist[]);
void optimize_table(actionlist[], mask_t *, mask_t *, int);

#endif
