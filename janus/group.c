
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */


#include <grp.h>
#include <sys/types.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "sysxlat.h"
#include "module.h"
#include "debug.h"

#define HOOK_T action (*)(const prstat_t *, void *)


typedef struct __state {
    struct __state * next;
    unsigned char * name;
} state_t;

static int group_allowed(state_t * state, janus_gid_t group)
{
    struct group  *gp;

    while(state) {
        gp = getgrnam(state->name);

        if (gp && gp->gr_gid == group) {
            return 1;
        }
        
        state = state->next;
    }

    return 0;
}

//we will only allow a setgroups call if we match
//all of its groups
static action setgroups_hook(const prstat_t * p, state_t * state)
{
    int i;
    int num_groups = p->args[0];
    janus_gid_t groups[NGROUPS_MAX];
    
    if (num_groups > NGROUPS_MAX || num_groups < 0)
        return deny(DENY_DEFAULT,"Tried to setgroups to an unauthorized group.");

    PDEBUG("num groups %d",num_groups);

    if (fetcharg(p->pcb,1,groups,num_groups * sizeof(janus_gid_t),TYPE_POINTER)) 
        return deny(DENY_DEFAULT,"Error reading group list.");

    for (i = 0; i < num_groups; i++) {
        assert(groups[i] > 0);

        if (!group_allowed(state,groups[i])) 
            return NO_COMMENT;
    }
    
    return ALLOW;
}

static action setgid_hook(const prstat_t * p, state_t * state)
{
    janus_gid_t gid = (unsigned short)p->args[0];
    
    /* Check for casting tricks (e.g., passing 1<<16, if janus_gid_t == short). */
    if (p->args[0] != (janus_gid_t)gid)
        return deny(DENY_DEFAULT,"setgid call failed cast check.");

    return group_allowed(state, gid) ? ALLOW : NO_COMMENT;
}

static void usage()
{
    PINFO("Usage: group allow group,group...\n");
}

static void *	init(const char *conf_line)
{
    char * tptr, * conf_str; 
    state_t * sptr, * head;

    if (!conf_line) {
        usage();
        return INIT_FAIL;
    }

    conf_str = strdup(conf_line);    
    assert(conf_str);

    tptr = strtok(conf_str," \t,");
    
    if (strcmp(tptr,"allow")) {
        usage();
        return INIT_FAIL;
    }

    tptr = strtok(NULL," \t,");

    if (!tptr) {
        usage();
        return INIT_FAIL;
    }


    sptr =  (state_t *)malloc(sizeof(state_t));
    assert(sptr);

    sptr->name = strdup(tptr);
    assert(sptr->name);
    
    sptr->next = NULL;
    head = sptr;

    tptr = strtok(NULL," \t,");

    while (tptr) {
        sptr->next = (state_t *)malloc(sizeof(state_t));
        assert(sptr->next);
        sptr = sptr->next;
        sptr->next = NULL;
        sptr->name = strdup(tptr);
        assert(sptr->name);
        tptr = strtok(NULL," \t,");
    }
    
    free(conf_str);

    return head; 
}

static syscall_entry   entries[] = {
    {SYS_setgid, FUNC,(HOOK_T)setgid_hook},
    {SYS_setgroups, FUNC,(HOOK_T)setgroups_hook},

};

static const int	nentries = sizeof(entries) / sizeof(syscall_entry);

void * group_init(const char * conf) { return init(conf); }
int group_num_entries() { return nentries; }
const syscall_entry * group_get_entries() { return entries; }
    


