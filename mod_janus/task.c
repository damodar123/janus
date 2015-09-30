
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#define __NO_VERSION__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/sched.h>   /* for wait queues and current  and find_task */
#include<asm/system.h>     /*for cli() etc.. */ 

#include "modtools.h"

#define STATIC static  


/* Get task structure from PID. 
   We'd like to use find_task_by_pid(), but it's not exported (argh!),
   so we have to re-implement the same functionality. */
struct task_struct * fetch_task_by_pid(pid_t pid)
{
    struct task_struct *p = current;

    do {
        if (p->pid == pid)
            return p;

        p = p->next_task;

    } while (p != current);
    
    PDEBUG("fetchtask by pid failed");

    return NULL;
}

#ifdef OLD_FASHION

static struct task_struct **mypidhash;

void init_task_hash()
{
    struct task_struct **spptr = current->pidhash_pprev;
    mypidhash = spptr - pid_hashfn(current->pid);
}


struct task_struct *fetch_task_by_pid(int pid)
{
    struct task_struct *p, **htable = &mypidhash[pid_hashfn(pid)];

    for (p = *htable; p && p->pid != pid; p = p->pidhash_next);

    return p;
}

#endif


/* We wanted to just call add_to_runqueue(), etc., from kernel/sched.c.
   But, those symbols weren't exported, so we were forced to
   cut-and-paste code (argh).
   Be warned: Since the init_task and nr_running symbols weren't
   exported, even a straightforward cut-and-paste doesn't work.
   We replace init_task with fetch_task_by_pid(0).  It's not clear
   why this is correct or why it works, but it does work.
   It's not clear how nr_running can be replaced, but since it is only
   used to compute load averages, it doesn't seem to bad to fail to update it.
   Therefore, we don't update nr_running below.  Fortunately, the incorrect
   value of the load average will be only temporary, so there seems to be
   little harm from this. */

STATIC inline void add_to_runqueue(struct task_struct * p)
{
    //note yes this really is supposed to be pid 0!!

    struct task_struct * initp = fetch_task_by_pid(0);
	struct task_struct * next = initp->next_run;

    kassert(initp);
    kassert(p); 
    kassert(next); 

	p->prev_run = initp;
	initp->next_run = p;
	p->next_run = next;
	next->prev_run = p;
}

STATIC inline void del_from_runqueue(struct task_struct * p)
{
	struct task_struct *next = p->next_run;
	struct task_struct *prev = p->prev_run;
    
    kassert(next);
    kassert(prev);
    kassert(p);

	next->prev_run = prev;
	prev->next_run = next;
	p->next_run = NULL;
	p->prev_run = NULL;
}

/*
 * Wake up a process. Put it on the run-queue if it's not
 * already there.  The "current" process is always on the
 * run-queue (except when the actual re-schedule is in
 * progress), and as such you're allowed to do the simpler
 * "current->state = TASK_RUNNING" to mark yourself runnable
 * without the overhead of this.
 */

/* For safety I lock things up before I
 mess with the runqueue, since I can't grab a
 proper spin lock I just grab the big lock*/

void restart_task(struct task_struct * p)
{
	unsigned long flags;
    kassert(p);

    save_flags(flags);
    cli();

	p->state = TASK_RUNNING;        
	add_to_runqueue(p);

    restore_flags(flags);

}

void stop_task(struct task_struct * p)
{
	unsigned long flags;
    kassert(p);

    save_flags(flags);
    cli();
    	
	p->state = TASK_UNINTERRUPTIBLE;        
	del_from_runqueue(p);

    restore_flags(flags);
}

    
