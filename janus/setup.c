/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "trace.h"
#include "systable.h"
#include "sysxlat.h"
#include "debug.h"
#include "childstate.h"
#include "module.h"
#include "main.h"

#define MAXLINELENGTH 2048

typedef struct {
    char * name;
    void * (*init)(const char *);
    int (*num_entries)();
    const syscall_entry * (*get_entries)();
} mod_tab_entry;

typedef struct {
    const char * name;
    int (*parse_arg)(const char *);
} builtin_tab_entry;

static builtin_tab_entry builtin_tab[] = {
    /* {"log_level",main_set_log_level}, */
    /* {"kill_level",main_set_kill_level}, */
    /* {"shutdown_level",main_set_shutdown_level}, */
    {"starting_dir",childstate_set_starting_dir},
    {"starting_uid",childstate_set_starting_uid},
    {"starting_gid",childstate_set_starting_gid},
    /* {"starting_priority",childstate_set_starting_priority}, */
    {"starting_env",childstate_putenv},
    {"process_limit",childstate_putrlimit},
    {NULL,0},
};

static mod_tab_entry mod_init_tab[] = {
    {"net",net_init,net_num_entries,net_get_entries},
    {"path",path_init,path_num_entries,path_get_entries},
    {"uid",uid_init,uid_num_entries,uid_get_entries},
    {"group",group_init,group_num_entries,group_get_entries},
    {"force_allow",force_allow_init,force_allow_num_entries,force_allow_get_entries},
    {NULL,0,0,0},
};

static const mod_tab_entry mod_basic_entry =
    {"basic",basic_init,basic_num_entries,basic_get_entries};

static mod_tab_entry * lookup_mod(char * mname)
{
    int i;
    
    for (i = 0; mod_init_tab[i].name && strcmp(mod_init_tab[i].name,mname); i++)
        ;
    
    return mod_init_tab[i].name ? mod_init_tab + i : NULL;
}

static builtin_tab_entry * lookup_builtin(char * name)
{
    int i;
    
    for (i = 0; builtin_tab[i].name && strcmp(builtin_tab[i].name,name); i++)
        ;
    
    return builtin_tab[i].name ? builtin_tab + i : NULL;
}

static int parse_builtin(char * directive,char * conf_line)
{
    builtin_tab_entry * bp = lookup_builtin(directive);
    assert(bp);
    return bp->parse_arg(conf_line);
}

static int load_module(const mod_tab_entry *mptr,
                 char * conf_line, actionlist systable[NSYSCALL])
{
    void * (*init)(const char *);
    const syscall_entry * entries;
    int num_entries;
    void *state;
    int i;
    assert(mptr);

    init = mptr->init;
         
    //initialize module

    state = (*init) (conf_line);

    if (state == INIT_FAIL) 
        return -1;
    
    entries = mptr->get_entries();
    num_entries = mptr->num_entries();

        /* Load the entries into the table */
    for (i = 0; i < num_entries; ++i) {
        /* Allocate a new node and link it in */
        actionnode *new =
            (actionnode *) malloc(sizeof(actionnode));

        assert(new);

        new->kind = entries[i].kind;
        new->hook = entries[i].hook;
        new->state = state;
        new->next = NULL;
        *(systable[entries[i].which].tail) = new;
        systable[entries[i].which].tail = &(new->next);
    }

    return 0;
}


/* Setup the supplied systable with the given config file.
   conf should be at the beginning of the file.
   systable should be initialized properly. */
static void process_policy(FILE * conf, actionlist systable[NSYSCALL])
{
    char buf[MAXLINELENGTH];
    int line_no = 0;
    mod_tab_entry * mptr;

    /* Always load the basic module. */
    if(load_module(&mod_basic_entry,"",systable)) {
        PINFO("Couldn't load `basic' module.");
        exit(1);
    }

    while (fgets(buf, MAXLINELENGTH - 1, conf)) {
        char *nl, *sp, *fn;
        line_no++;


        /* Check for a newline */
        nl = strchr(buf, '\n');

        if (!nl) {
            fprintf(stderr, "Line too long in config file!\n");
            exit(1);
        }

        /* Zap the newline */
        *nl = '\0';

        /* Strip leading whitespace */
        fn = buf;
        while (*fn == ' ' || *fn == '\t')
            ++fn;

        /* Check for blank lines or comments */
        if (*fn == '#' || *fn == '\0')
            continue;

        /* Find the first space or tab */
        sp = fn;
        while (*sp != ' ' && *sp != '\t' && *sp != '\0')
            ++sp;

        if (*sp) {
            *sp = '\0';
            ++sp;

            /* Strip leading whitespace from the args */
            while (*sp == ' ' || *sp == '\t')
                    ++sp;
        }
            
        /*Built-in stuff */

                    
        if (lookup_builtin(fn)) {
            if (parse_builtin(fn,sp)) {
                PINFO("Error in %s on line 
                     %d of policy file.\n",fn,line_no);
                exit(1);
            }

        } else if ((mptr = lookup_mod(fn)) != NULL) {
            if (load_module(mptr,sp,systable)) {
                PINFO("Module %s initialization failed, error on line 
                     %d of policy file.\n",fn,line_no);
                exit(1);
            }
        } else {
            PINFO("Unrecognized option \"%s\" on line %d of policy file.",fn,line_no);
            exit(1);
        }


    } 


}

void setup_config_init_tables(FILE * conf, actionlist systable[NSYSCALL],int show_policy)
{
    mask_t sysentryset, sysexitset;
    int i;
    //clean up everyone
    /* Initialize the systable */

    for (i = 0; i < NSYSCALL; ++i) {
        systable[i].head = NULL;
        systable[i].tail = &(systable[i].head);
    }


    init_childstate();
    
    //setup stuff
    process_policy(conf, systable);
    
    clear_mask(&sysentryset);
    clear_mask(&sysexitset);
    
    //compute traps
    optimize_table(systable, &sysentryset, &sysexitset, show_policy);
    
    //install traps
    set_global_mask(sysentryset, sysexitset);
}

static void delete_node(actionnode ** node)
{
    actionnode *tofree;

    /* Be paranoid */
    if (!node || !*node)
        return;

    tofree = *node;
    *node = (*node)->next;
    free(tofree);
}

/*
static void delete_entries(actionnode ** node)
{
    while (node && *node) {
        if ((*node)->kind != EXIT_FUNC) {
            delete_node(node);
        } else {
            node = &((*node)->next);
        }
    }
}
*/

/* Optimize the systable, and mark which syscalls need to be watched for
    entry and/or exit */
void optimize_table(actionlist systable[NSYSCALL], mask_t * entryset,
                    mask_t * exitset, int show_policy)
{
    int sysc;
    actionnode **previfshort, **current, **nextcurrent;
    int entryhandle, exithandle;
    action justallow;

    for (sysc = 0; sysc < NSYSCALL; ++sysc) {
        entryhandle = 1;
        exithandle = 0;
        current = &(systable[sysc].head);
        previfshort = NULL;
        justallow = NO_COMMENT;

        /* Go through the list and remove redundant things */
        while (*current) {
            /* What should we do with this? */
            switch ((*current)->kind) {
            case NO_COMMENT:
                /* This is a useless node; delete it. */
                delete_node(current);
                break;
            case DENY:
            case ALLOW:
                entryhandle = 1;
                if (justallow != FUNC)
                    justallow = (*current)->kind;

                /* Remember the next node */
                nextcurrent = &((*current)->next);

                /* If the previous node was a shortcut, delete it,
                   because it would be superceded by this one */
                if (previfshort) {
                    delete_node(previfshort);
                } else {
                    previfshort = current;
                }

                /* This node is a shortcut; advance the current node */
                current = nextcurrent;

                /* Advance the previfshort pointer past EXIT_FUNCs,
                   if necessary */
                while (previfshort && *previfshort &&
                       (*previfshort)->kind == EXIT_FUNC) {
                    previfshort = &((*previfshort)->next);
                }

                break;

            case FUNC:
                /* Leave the entry handler alone. */
                entryhandle = 1;
                justallow = FUNC;

                /* This node is not a shortcut; advance the current node */
                previfshort = NULL;
                current = &((*current)->next);
                break;

            case EXIT_FUNC:
                /* Leave the exit handler alone. */
                exithandle = 1;

                /* Advance the current node */
                current = &((*current)->next);
                break;

            default:
                /* This is a bad node; delete it. */
                fprintf(stderr, "Error: Bad kind (%d); deleting node.\n",
                        (*current)->kind);
                delete_node(current);
                break;
            }
        }

        /* Keep the tail of the list right */
        systable[sysc].tail = current;

        /* Add this syscall to the list of those to trap on exit */
        if (exithandle) 
            addtomask(exitset, sysc);

        /* Add this syscall to the list of those to trap on entry */
        if (entryhandle && (justallow != ALLOW))
            addtomask(entryset, sysc);

        
        if (show_policy && strncmp(xlat_callnum(sysc), "SYS_", 4)) {
            fprintf(stderr, "%20s\t\t", xlat_callnum(sysc));

            if (entryhandle)
                switch (justallow) {
                    case ALLOW :
                        fprintf(stderr,"ALLOW");
                        break;
                    case DENY: 
                        fprintf(stderr,"DENY");
                        break;
                    case FUNC:
                        fprintf(stderr,"TRAP_ENTRY");
                        break;
                    case NO_COMMENT:
                        fprintf(stderr,"DENY/NO_COMMENT");
                        break;
                    default:
                        fprintf(stderr,"UNKNOWN TYPE");
                        break;
                }

            if (exithandle) 
                fprintf(stderr,"TRAP_EXIT\t");

            if (!entryhandle && !exithandle && (systable[sysc].head == NULL)) 
                    fprintf(stderr, "DENY/NOT_HANDLED");
            
            fprintf(stderr,"\n");

        }
    }
}
