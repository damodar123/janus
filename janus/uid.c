
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* handy module for allowing calls explicity without
the need to code a new module */

#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
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


static action setuid_hook(const prstat_t * p, state_t * state)
{
    struct passwd  *pw;
    uid_t uid = (uid_t) p->args[0];

    /* Watch out for casting tricks */
    if (p->args[0] != (long)uid)
        return deny(DENY_DEFAULT,"uid to setuid failed cast check.");

    while(state) {
        pw = getpwnam(state->name);

        PDEBUG("checking %s",state->name); 
            
        if (pw && pw->pw_uid == p->args[0])
            return ALLOW;
        
        state = state->next;
    }

    return NO_COMMENT;
}

static void usage()
{
        PINFO("Usage: uid allow user,user...\n");
}

static void *	init(const char *conf_line)
{
    char * tptr, * conf_str; 
    state_t * sptr, * head;

    if (!conf_line) {
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
    {SYS_getuid, ALLOW, 0},
    {SYS_setuid, FUNC,(HOOK_T)setuid_hook},

};

static const int	nentries = sizeof(entries) / sizeof(syscall_entry);

/* module interface */

void * uid_init(const char * conf) { return init(conf); }
int uid_num_entries() { return nentries; }
const syscall_entry * uid_get_entries() { return entries; }
    


