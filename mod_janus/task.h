
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */


#ifndef TASK_H
#define TASK_H

int stop_task(struct task_struct * tp);
int restart_task(struct task_struct * tp);

/* void init_task_hash(); */
struct task_struct * fetch_task_by_pid(int pid);

#endif
