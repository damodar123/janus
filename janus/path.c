 /*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "debug.h"
#include "sysxlat.h"
#include "trace.h"
#include "module.h"


extern int match(const char *, const char *);


/* I'm going to be very evil and | the flags together.  Don't mind me. */
/* Note: If you add any other modes here, do all of the following:
   1. Ensure the new mode is defined as a new power of 2.
   2. Update the definition of ALL to include the new mode.
   3. Update the list of modes below.
   4. Update parse_mode(). */
typedef enum { 
        NONE = 0x0, READ = 0x1, WRITE = 0x2, EXEC = 0x4, 
        DELETE = 0x8, CHDIR = 0x10,
        ALL = READ | WRITE | EXEC | DELETE | CHDIR } ac_mode_t;

static ac_mode_t modes[] = { READ, WRITE, EXEC, DELETE,CHDIR };
static int nmodes = sizeof(modes)/sizeof(ac_mode_t);

typedef struct node_s {
    action upon_match;
    ac_mode_t mode;
    char *pattern;
    struct node_s *next;
} node;

/* I'm very evil: this is both an action and an ac_mode_t.  Don't mind me. */
#define ERR -1

node gl_head_node = { ERR, ERR, (char *) 0, (node *) 0 };
node *gl_list = &gl_head_node;

typedef enum { ACTIVE, PASSIVE } status_t;

/*
 * 'str' may be read, write, exec, unlink, r, w, x, u
 * or it may be a comma-separated list of some combination of the above
 * (no spaces between commas!)
 * in the case of a list of r, w, x, d, commas can be ommitted.
 * parse this string, and return the access mode.
 * beware, I call strtok.  deal with it.
 */
static ac_mode_t parse_mode(char *str)
{
    ac_mode_t rv = 0;
    char *p;

    if (strspn(str, "rwxd") == strlen(str)) {
        for (; *str; str++)
            switch (*str) {
                case 'r': rv |= READ; break;
                case 'w': rv |= WRITE; break;
                case 'x': rv |= EXEC; break;
                case 'u': rv |= DELETE; break;
            }
        return (rv);
    }

    for (p = strtok(str, ","); p; p = strtok((char *) 0, ","))
        if (strcmp(p, "read") == 0)
            rv |= READ;
        else if (strcmp(p, "write") == 0)
            rv |= WRITE;
        else if (strcmp(p, "exec") == 0)
            rv |= EXEC;
        else if (strcmp(p, "unlink") == 0)
            rv |= DELETE;
        /* else if (strcmp(p, "chdir") == 0) */
            /* rv |= CHDIR; */
        else
            return (ERR);
    return (rv);
}

static action parse_upon_match(char *str)
{
    if (strcmp(str, "allow") == 0)
        return (ALLOW);
    else if (strcmp(str, "deny") == 0)
        return (DENY);
    return (ERR);
}

static int verify_absolute(char * path)
{
    /* No .. funniness. */
    if (strstr(path, "/../") 
        || strstr(path, "../") == path
        || strcmp(path, "..") == 0
        || (strstr(path, "/..") == path + strlen(path) - 3) 
        || strstr(path, "/./")
        || strstr(path, "/.") == path + strlen(path) - 2
        || (strlen(path) > 1 && path[strlen(path)-1] == '/'))
        return 0;
    
    /* No relative paths; only absolute paths. */
    if (*path != '/')
        return 0;
    
    return 1;
}

/* parses open() flags, translates them into ac_mode_t */
static ac_mode_t f2am(mode_t o_flags)
{
    ac_mode_t m = 0;

    /* Hmm: If O_TRUNC is specified, should we require DELETE privilege, too? */
    if (o_flags & (O_TRUNC | O_CREAT | O_APPEND))
        m |= WRITE;

    switch (o_flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
        case O_RDONLY:
            return (m | READ);
        case O_WRONLY:
            return (m | WRITE);
        case O_RDWR:
            return (m | READ | WRITE);
        default:
            fprintf(stderr, "bad open flag %ld\n", (long) o_flags);
            return (ERR);            /* paranoia */
    }
}

/*
 * for ONE mode (e.g. READ, WRITE, or EXEC, but NOT a combination!),
 * runs through the whole linked list and verifies access is allowed.
 */
static action check_one_access(const char *arg, ac_mode_t m)
{
    node *np;
    action todo = NO_COMMENT;

    assert(!(m & (m-1))); /* not allowed to specify more than one mode here */

    for (np = gl_list->next; np; np = np->next)
        if ((m & np->mode) && match(np->pattern, arg))
            switch (np->upon_match) {
                case NO_COMMENT: break;
                case DENY: todo = DENY; break;
                case ALLOW: todo = ALLOW; break;
                default:
                    fprintf(stderr, "path err: burp!\n");
                    return (DENY);    /* should never get here */
            }
    return (todo);
}



/*
 * the general access checker.
 * takes a path name (arg0ptr) and a requested access type (access_flags).
 * returns the action that should be taken on this type of access request.
 * 
 * for each type of access requested, we independently check
 * whether that access is allowed, and then combine the results in stop().
 * we combine in an &&-like stage, where DENY takes precedence over
 * ALLOW/NO_COMMENT, and NO_COMMENT takes precedence over ALLOW.
 * 
 * Usage:
 *   start(pcb)
 *   request(arg0ptr, m)
 *   request(arg1ptr, n)
 *   ...
 *   result = stop()
 */

/* for use only by start(), request(), stop() */
static int cur_started = 0;
static int cur_allows, cur_nocoms, cur_denies;
static pcb_t *cur_pcb;

static void start(pcb_t * pcb)
{
    cur_started = 1;
    cur_allows = cur_nocoms = cur_denies = 0;
    cur_pcb = pcb;
}

/*
 * hack.  hack.  hack.  for symlink(), who needs to do the fetchstr()
 * itself, and then munge the result, and *then* call request().  sigh.
 */
static void request_local_buf(char *arg, ac_mode_t m)
{
    int i;

    /*
     * note optimization (because we're implementing the equivalent of `&&'):
     * if cur_denies > 0, can just immediately return.
     */

    if (!cur_started || !arg || m == ERR || cur_denies > 0) {
        cur_denies++;
        return;
    }

    /* arg = canonicalize(arg); */

    if (!arg) {
        cur_denies++;
        return;
    }

    for (i = 0; i < nmodes; i++) {
        if (modes[i] & m) {
            switch (check_one_access(arg, modes[i])) {
                case DENY: cur_denies++; return;
                case NO_COMMENT: cur_nocoms++; break;
                case ALLOW: cur_allows++; break;
                default:
                    fprintf(stderr, "path err: the impossible, wasn't!\n");
                    cur_denies++;
                    assert(0); /* shouldn't happen! */
                }
        }
        m &= ~modes[i];
    }
    assert(!m);
}

static void request(const long arg0ptr, ac_mode_t m)
{
    char p1[PATH_MAX];
    char p2[PATH_MAX];
    int err1,err2;

    err1 = fetcharg(cur_pcb, 0, p1,PATH_MAX, TYPE_PATH_FOLLOW);
    err2 = fetcharg(cur_pcb, 0, p2,PATH_MAX, TYPE_PATH_NOFOLLOW);

    if (!cur_started || err1 || err2) {
        cur_denies++;
        return;
    }

    request_local_buf(p1, m);
    request_local_buf(p2, m);
}


static action stop(void)
{
    action a = NO_COMMENT;

    /* order is important */
    if (cur_denies > 0)
        a = DENY;
    else if (cur_nocoms > 0)
        a = NO_COMMENT;
    else if (cur_allows > 0)
        a = ALLOW;

    cur_started = 0;

    return (a);
}

/* the same everywhere.  for clarity. */
#define HOOK_ARGS const prstat_t *p, void *v
#define HOOK_START { assert((status_t) v == ACTIVE); start(p->pcb); }
#define     HOOK_STOP return(stop());
#define ARG(i)     (p->args[i])    /* the i-th arg to the syscall */

static action open_hook(HOOK_ARGS)
{
    HOOK_START
    if ((ARG(1) & O_CREAT)        /* mode ignored unless O_CREAT is used */
        &&(mode_t) ARG(2) & (S_ISUID | S_ISGID | S_ISVTX))
        return (DENY);         /* no setuid, setgid, save-text files allowed */
    request(ARG(0), f2am((mode_t) ARG(1)));
    HOOK_STOP
}

/* equivalent to open(., O_WRONLY|O_CREAT|O_TRUNC, .), says the manual */
static action creat_hook(HOOK_ARGS)
{
    HOOK_START
    if ((mode_t) ARG(1) & (S_ISUID | S_ISGID | S_ISVTX))
        return (DENY);         /* no setuid, setgid, save-text files allowed */
    request(ARG(0), f2am((mode_t) O_WRONLY | O_CREAT | O_TRUNC));
    HOOK_STOP
}

static action symlink_hook(HOOK_ARGS)
{
    return deny(DENY_DEFAULT, "Symlink creation disallowed to prevent races!");
}

static action link_or_rename_hook(HOOK_ARGS)
{
    char a1[PATH_MAX],a2[PATH_MAX];
    action mayexec1, mayexec2;

    HOOK_START
    request(ARG(0), READ | WRITE);
    request(ARG(1), WRITE);
        
    if (fetcharg(p->pcb, 0, a1, PATH_MAX,TYPE_PATH_FOLLOW) ||
         fetcharg(p->pcb, 0, a2, PATH_MAX,TYPE_PATH_NOFOLLOW))
        return deny(DENY_DEFAULT,"Error fetching paths.");

    /* check that ARG(0) is not a symlink */
    if (strcmp(a1,a2)) {
        return deny(DENY_DEFAULT,
            "Renaming/linking of symlinks is forbidden to prevent races.");
    }

    /*
     * Gunk: if app has execute permission on ARG(1), don't let it do
     * do the link/rename unless it has execute permission on ARG(0) too.
     */

    mayexec1 = check_one_access(a1, EXEC);
    if (mayexec1 == ALLOW) 
        request(ARG(0), EXEC);
    
    mayexec2 = check_one_access(a2, EXEC);
    if (mayexec2 == ALLOW) 
        request(ARG(0), EXEC);

    HOOK_STOP
}

static action unlink_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), DELETE);
    HOOK_STOP
}

#ifdef USE_IF_NEEDED
static action mknod_hook(HOOK_ARGS)
{
    HOOK_START
    if (((mode_t) ARG(1) & S_IFMT) != S_IFIFO)
        return (DENY);
    /* no setuid, setgid, save-text files allowed */
    if ((mode_t) ARG(1) & (S_ISUID | S_ISGID | S_ISVTX))
        return (DENY);
    request(ARG(0), WRITE);
    HOOK_STOP
} 
#endif

static action mkdir_hook(HOOK_ARGS)
{
    HOOK_START
    if ((mode_t) ARG(1) & S_ISUID)
        return (DENY);            /* paranoia! setuid dirs are meaningless */
    request(ARG(0), WRITE);
    HOOK_STOP
}

static action rmdir_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), DELETE);
    HOOK_STOP
}


/*
 * Note that we require not only read&exec privileges to exec something,
 * but we also insist it not be setuid or setgid.  The claim is that
 * the way we currently use /proc will ensure that exec()ing a setuid
 * or setgid file will not be possible.
 */


static action execve_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), READ | EXEC);
    HOOK_STOP
}

static action utime_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), WRITE);
    HOOK_STOP
}

static action stat_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), READ);
    HOOK_STOP
}

static action lstat_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), READ);
    HOOK_STOP
}

static action readlink_hook(HOOK_ARGS)
{
    HOOK_START
    request(ARG(0), READ);
    HOOK_STOP
}

/*
 * BUG: against my better judgement, I'm enabling use of access().
 * Some important programs (e.g. /bin/sh) depend on access (!!),
 * so I think this is a necessary evil.
 * Still, that doesn't mean I have to leave it totally unrestricted,
 * and it doesn't mean I have to like it. :-)
 * 
 * (I really hate access(), because it has a race condition, and
 * thus its return value is not trustworthy -- yet every program that
 * ever calls it, trusts its return value.  It's very existence
 * is (IMHO) a bug with security consequences.  Grrr.)
 */
static action access_hook(HOOK_ARGS)
{
    ac_mode_t m;

    HOOK_START

    /* we end up verifying the existence of the file, always. :-) */
    m = READ;

    m |= (ARG(1) & (R_OK | F_OK)) ? READ : 0;
    m |= (ARG(1) & W_OK) ? WRITE : 0;
    m |= (ARG(1) & X_OK) ? EXEC : 0;
    request(ARG(0), m);

    HOOK_STOP
}

/* makes it the right type for the syscall_entry table */
#define HOOK_T action (*)(const prstat_t *, void *)

/* syscalls I don't understand; thus deny & wait & see if anything breaks */
#define UNKNOWN DENY

/* the syscall_entry table is required */
static const syscall_entry entries[] = {
    {SYS_open, FUNC, (HOOK_T) open_hook},
    {SYS_creat, FUNC, (HOOK_T) creat_hook},
    {SYS_symlink, FUNC, (HOOK_T) symlink_hook},
    {SYS_link, FUNC, (HOOK_T) link_or_rename_hook},
    {SYS_unlink, FUNC, (HOOK_T) unlink_hook},
    {SYS_chdir, ALLOW, 0},
    {SYS_mkdir, FUNC, (HOOK_T) mkdir_hook},
    {SYS_rmdir, FUNC, (HOOK_T) rmdir_hook},
    {SYS_rename, FUNC, (HOOK_T) link_or_rename_hook},
    {SYS_utime, FUNC, (HOOK_T) utime_hook},
    {SYS_close, ALLOW, (HOOK_T) 0},
    {SYS_fstat, ALLOW, (HOOK_T) 0},
    {SYS_sync, ALLOW, (HOOK_T) 0},
    {SYS_readlink, FUNC, (HOOK_T) readlink_hook},
    {SYS_fstatfs, ALLOW, (HOOK_T) 0},
    {SYS_statfs, FUNC, (HOOK_T) stat_hook},
    {SYS_stat, FUNC, (HOOK_T) stat_hook},
    {SYS_lstat, FUNC, (HOOK_T) lstat_hook},
    {SYS_sysfs, UNKNOWN, (HOOK_T) 0},
    {SYS_access, FUNC, (HOOK_T) access_hook},
    {SYS_fchdir, DENY, (HOOK_T) 0},
    {SYS_execve, FUNC, (HOOK_T) execve_hook},
};
static const int nentries = sizeof(entries) / sizeof(syscall_entry);


static int invocations = 0;

/* parse the args, save 'em in the linked list, and return a context */
static void *init(const char *conf_line)
{
    char *p, *arg = NULL, *pum, *pmo;
    char *error_msg = NULL;
    node *np, *nq;
    action um;
    ac_mode_t mo;

#define FAIL(err) {error_msg = err; goto fail;}

    if (!conf_line)
        FAIL("no arguments")
    arg = strdup(conf_line);
    if (!arg)
        FAIL("malloc failed")

    p = strchr(arg, '#');
    if (p)
        *p = '\0';

    pum = strtok(arg, " \t");
    pmo = strtok(NULL, " \t");

    /* save rest of arg [for strtok() reentrance] */
    p = strtok(NULL, "");

    /* placed here, not earlier, because they may wanna use strtok() */
    if ((um = parse_upon_match(pum)) == ERR)
        FAIL("bad args: no allow/deny")
    if ((mo = parse_mode(pmo)) == ERR)
        FAIL("bad args: no access mode")

    /* go to end of linked list */
    for (np = gl_list; np->next; np = np->next)
        ;

    /* append patterns to end of linked list */
    for (p = strtok(p, " \t"); p; p = strtok((char *) 0, " \t")) {
        nq = (node *) malloc(sizeof(node));
        if (!nq)
            FAIL("malloc failed");

        nq->upon_match = um;
        nq->mode = mo;
        
        if (!verify_absolute(p))
            FAIL("All paths must be absolute.");

        nq->pattern = strdup(p);
        if (!nq->pattern) {
            free(nq);
            FAIL("strdup failed")
        }
        nq->next = np->next;
        np->next = nq;
        np = nq;
    }

    free(arg);

    invocations++;
    return ((void *) (invocations==1 ? ACTIVE : PASSIVE));

#undef FAIL

  fail:
    if (error_msg)
        fprintf(stderr, "path error: %s\n", error_msg);
    if (arg)
        free(arg);
    return ((void *) INIT_FAIL);
}


void * path_init(const char * conf) { return init(conf); }
int path_num_entries()
{
    return invocations==1 ? nentries : 0;
}
const syscall_entry * path_get_entries()
{
    return invocations==1 ? entries : NULL;
}
    



/*

MINOR UNRESOLVED ISSUES & BUGS:
    File creation: is governed by access permissions on the filename,
        NOT by those on the parent directory (ala Unix).  Change?
    I enabled access(), since some programs (e.g. /bin/sh) seem to require
        it.  See comments in the source for more info.  Any problems here?
    Should we allow stat()s on `..', etc. so that getcwd() works?
    Specifying `exec' without `read' is pointless.  I could've made the
        `exec' keyword automagically control `read' access too, but I
        figured it's better to force the config file to be explicit, so
        there's no confusion.  Any complaints?

ASSUMPTIONS & INTER-MODULE DEPENDENCIES:
    All fd's closed before helper app is started.  Passing fd's through
        AF_UNIX sockets is disallowed by some other module.  There is no
        other way to pass fd's.
    Umask is set before helper app is started.
    Core dumps will be disabled by some other module (e.g. ulimit 0?).
    Access to /proc must be disallowed (explicitly, in the config file).
    If the confined application can read a file, assume that it can leak
        that information out over the network via some covert channel.
        Thus, must control all reads carefully (explicitly, in the config file).
*/
