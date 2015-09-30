/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* checks network connections */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/net.h>
#include <linux/un.h>

#include "module.h"
#include "trace.h"
#include "debug.h"
#include "sysxlat.h"
#include "glob.h"


/* extern char **environ, **traced_environ; */

#define FETCHARG_ERROR deny(DENY_DEFAULT,"Unable to read syscall argument.")

typedef enum { TCP = 1, UDP = 2 } proto_type;
typedef enum { CONNECT = 1, BIND = 2 } sockcall_t;

typedef struct {
    int is_unix_domain;
    proto_type ptype;
    unsigned long addr, addr_mask;
    unsigned short port, port_mask;
    action what;
    int deny_level;
    sockcall_t sockcall;
    char path_pattern[UNIX_PATH_MAX];
} state_t;

static void print_state(state_t * state)
{
    struct in_addr in = {state->addr};
    struct in_addr mask = {state->addr_mask};
    PDEBUG("net %s %s %s",
        (state->what == ALLOW) ? "ALLOW" : "DENY",
        (state->sockcall == CONNECT) ? "CONNECT" : "BIND", 
        (state->ptype == TCP) ? "TCP" : "UDP");

    if (state->is_unix_domain)
        PDEBUG("%s",state->path_pattern);
    else { 
        char * inp = strdup(inet_ntoa(in));
        char * maskp = strdup(inet_ntoa(mask));

        PDEBUG("%s/%s %hd/%hd",inp,maskp,
            ntohs(state->port),ntohs(state->port_mask));
        free(inp);
        free(maskp);

    }     

}

/* returns 1 if "address matches state_t wildcard", 0 otherwise */
static action check_inet(struct sockaddr_in * a, int size,int fetched_type,state_t * state)
{
    int type;

    switch(fetched_type) {
        case SOCK_DGRAM: 
            type = UDP; break;
        case SOCK_STREAM: 
            type = TCP; break;
        default: 
            return deny(DENY_DEFAULT,"Tried to bind/connect disallowed socket type");
    }

    assert(type == UDP || type == TCP);

    if (!(type & state->ptype))
        return NO_COMMENT;

    if (a->sin_family != AF_INET)
        return NO_COMMENT;

    if(size != sizeof(struct sockaddr_in))
        return deny(DENY_DEFAULT,"Invalid addr size to inet-domain socket call.");

    if ((a->sin_port & state->port_mask) != state->port)
        return NO_COMMENT;

    if ((a->sin_addr.s_addr & state->addr_mask) != state->addr)
        return NO_COMMENT;

    return state->what;
}

static action check_unix(struct sockaddr_un * a, int size, state_t * state)
{
    int i, ok = 0;

    if (size > sizeof(struct sockaddr_un) || size <= 0)
        return deny(DENY_DEFAULT,
            "Invalid addr size to unix-domain socket call.");  

    for (i=0; i<size; i++)
        if (a->sun_path[i] == '\0') {
            ok = 1; break;
        }
    if (!ok)
        return deny(DENY_DEFAULT,
            "Possible attack: Non-nul terminated string?");

    if (!state->is_unix_domain)
        return NO_COMMENT;

    if (a->sun_family != AF_UNIX)
        return NO_COMMENT;

    if (strcmp(state->path_pattern,a->sun_path))
        return NO_COMMENT;

    return state->what;
}

/* sockaddr_un is the largest type of sockaddr possible */
typedef struct sockaddr_un sockaddr_unknown;

/*
static void print_call(int call, int fd,sockaddr_unknown sa, int addrlen)
{
   PVERBOSE("%s({%d,%s,%d})\n",
        xlat_socketcall(call),
        fd,
        xlat_sockaddr((struct sockaddr *)&sa,addrlen),
        addrlen);
}
*/

static action check_common(const prstat_t * p,state_t * state)
{
    int fd,addrlen,fetched_type;
    sockaddr_unknown sa;

    bzero(&sa, sizeof(sa));
    if ((p->args[0] == SYS_BIND) || (p->args[0] == SYS_CONNECT)) {

        if (fetcharg(p->pcb,0,&fd,sizeof(int),TYPE_SCALAR)       
            || fetcharg(p->pcb,2,&addrlen,sizeof(int),TYPE_SCALAR)  
            || (addrlen > sizeof(sa) || addrlen <= 0)
            || fetcharg(p->pcb,1,&sa,addrlen,TYPE_SOCKADDR)          
            || fetch_sockettype(p->pcb,fd,&fetched_type)) 
                return FETCHARG_ERROR;

    } else if (p->args[0] == SYS_SENDTO) {
        if( fetcharg(p->pcb,0,&fd,sizeof(int),TYPE_SCALAR)
            || fetcharg(p->pcb,5,&addrlen,sizeof(int),TYPE_SCALAR)
            || (addrlen > sizeof(sa) || addrlen <= 0)
            || fetcharg(p->pcb,4,&sa,addrlen,TYPE_SOCKADDR)
            || fetch_sockettype(p->pcb,fd,&fetched_type))         
                return FETCHARG_ERROR;
    } else {
        fprintf(stderr, "Error: Invalid socket type in checkcommon\n");
        assert(0);
        exit(1);
    }


    if (sa.sun_family == AF_UNIX) {
        return check_unix((struct sockaddr_un *)&sa,addrlen,state);
    } else if (sa.sun_family == AF_INET) {
        return check_inet((struct sockaddr_in *)&sa,addrlen,fetched_type,state);
    } else {
        return deny(DENY_DEFAULT,"Invalid family in socketcall request");
    }
}
    
//only allow sends to stuff we can connect to
static action check_sendto(const prstat_t * p, state_t * state)
{
    if (state->sockcall != CONNECT)
        return NO_COMMENT;

    return check_common(p, state);
}

static action check_connect(const prstat_t * p, state_t * state)
{
    
    if (state->sockcall != CONNECT)
        return NO_COMMENT;

    return check_common(p, state);
}

static action check_bind(const prstat_t * p, state_t * state)
{
    if (state->sockcall != BIND)
        return NO_COMMENT;

    return check_common(p, state);
}

static action check_setsockopt(const prstat_t * p)
{
    int fd, level, optname, optlen;
    
    if (fetcharg(p->pcb,0,&fd,sizeof(int),TYPE_SCALAR))    
        return FETCHARG_ERROR; 
    if (fetcharg(p->pcb,1,&level,sizeof(int),TYPE_SCALAR))    
        return FETCHARG_ERROR; 
    if (fetcharg(p->pcb,2,&optname,sizeof(int),TYPE_SCALAR))    
        return FETCHARG_ERROR; 
    if (fetcharg(p->pcb,4,&optlen,sizeof(int),TYPE_SCALAR))    
        return FETCHARG_ERROR; 
    switch(level) {
        case SOL_SOCKET:
            switch(optname) {
                /* The only non-obvious one here is SO_REUSEADDR,
                   but I think that one is ok. */
                case SO_LINGER: case SO_REUSEADDR: case SO_SNDBUF:
                case SO_RCVBUF: case SO_SNDLOWAT: case SO_RCVLOWAT:
                case SO_KEEPALIVE:
                    return ALLOW;
                default:
                    return deny(DENY_DEFAULT, 
                       "Option <SOL_SOCKET,%X> not approved as safe.",
                       optname);
            }
        default:
            return deny(DENY_DEFAULT, "Bad socklevel.");
    }
}

static action check_socket(const prstat_t * p)
{
    int domain;
    int type;
    int protocol;

    if (fetcharg(p->pcb,0,&domain,sizeof(int),TYPE_SCALAR))    
        return deny(DENY_DEFAULT,"Error reading domain."); 
    if (fetcharg(p->pcb,1,&type,sizeof(int),TYPE_SCALAR))
        return deny(DENY_DEFAULT,"Error reading type.");
    if (fetcharg(p->pcb,2,&protocol,sizeof(int),TYPE_SCALAR))  
        return deny(DENY_DEFAULT,"Error reading protocol.");

    switch (type) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            break;
        default:
            return deny(DENY_DEFAULT,
                "socket type: %s not allowed, SOCK_STREAM/SOCK_DGRAM only.",
                xlat_socket_type(type));
    }

    switch (domain) {
        case AF_UNIX:
            if (protocol == 0)
                return ALLOW;
            return deny(DENY_DEFAULT,
                "AF_UNIX with unexpected protocol (%s).",
                    xlat_socket_protocol(protocol));
        case AF_INET:
            break;
        default:
            return deny(DENY_DEFAULT,
                "socket domain: %s not allowed, AF_INET/AF_UNIX only.",
                    xlat_socket_domain(domain));
    }

    /* Only some combinations of (domain,protocol) make sense.
       If you change the domain switch-statement above, be sure to
       change the protocol switch-statement below appropriately, because
       the code is inter-dependent.
       Think carefully.  Implement.  Then, change the assert() below.
       (The assert() is to remind you to engage brain before fingers.) */
    assert(domain == AF_INET);

    switch (protocol) {
        case IPPROTO_IP:
            break;
        case IPPROTO_TCP:
            if (type != SOCK_STREAM)
                return deny(DENY_DEFAULT,
              "TCP protocol can be used only with sockets of type SOCK_STREAM");
            break;
        case IPPROTO_UDP:
            if (type != SOCK_DGRAM)
                return deny(DENY_DEFAULT,
              "UDP protocol can be used only with sockets of type SOCK_DGRAM");
            break;
        default:
            return deny(DENY_DEFAULT,
                "socket protocol: %s not allowed, IP/TCP/UDP only.",
                    xlat_socket_protocol(protocol));
    }

    return ALLOW;
}


static action socketcall_hook(const prstat_t * p, void *st)
{
    state_t *state = (state_t *) st;

    switch (p->args[0]) {
    case SYS_GETSOCKNAME:
    case SYS_GETPEERNAME:
    case SYS_SEND:
    case SYS_RECV:
    case SYS_SHUTDOWN:
    case SYS_GETSOCKOPT:
        return ALLOW;
    case SYS_SOCKET:
        return check_socket(p);
    case SYS_BIND:
        return check_bind(p, state);
    case SYS_CONNECT:
        return check_connect(p, state);
    case SYS_LISTEN:
    case SYS_ACCEPT:
        return (state->sockcall == BIND) ? ALLOW : NO_COMMENT;
    case SYS_SENDTO:
        return check_sendto(p, state);
    case SYS_SETSOCKOPT:
        return check_setsockopt(p);
    case SYS_RECVFROM:
        return ALLOW;
    case SYS_SOCKETPAIR:
    /* These must be denied, otherwise it is possible for other processes
       to pass us already-opened file descriptors. */
    case SYS_SENDMSG:   
    case SYS_RECVMSG:
        fprintf(stderr, "DEBUG: denied socketcall %ld\n", p->args[0]);
        return DENY;
    default:
        fprintf(stderr, "DEBUG: unknown socketcall %ld\n", p->args[0]);
        return DENY;
    }
}

#ifdef SUPPORT_DISPLAY
static int parse_display(unsigned long *addr, unsigned short *port)
{
    char *dpy;
    char *colon;
    int dspnum;
    char **save_environ;

    save_environ = environ;
    environ = traced_environ;
    dpy = getenv("DISPLAY");
    environ = save_environ;
    if (!dpy) {
        return 0;
    }

    dpy = strdup(dpy);

    /* Find the colon */
    colon = strchr(dpy, ':');
    if (!colon) {
        free(dpy);
        return 1;
    }
    *colon = '\0';
    ++colon;

    /* Get the display number */
    if (sscanf(colon, "%d", &dspnum) < 1) {
        free(dpy);
        return 1;
    }
    *port = htons(6000 + dspnum);

    /* Get the host IP */
    if (*dpy == '\0') {
        *addr = inet_addr("127.0.0.1");
    } else if (*dpy >= '0' && *dpy <= '9') {
        struct hostent *hst = gethostbyname(dpy);
        *addr = inet_addr(dpy);
        if (!hst || !hst->h_addr_list || !*hst->h_addr_list) {
            free(dpy);
            return 1;
        }
        *addr = *(unsigned long *) (*hst->h_addr_list);
    }

    free(dpy);
    return 0;
}
#endif

static int parse_address(state_t * state, char *tok)
{
    int len;
    char * mask = strchr(tok,'/');

    /* Keyword that matches every possible IP address */
    if (!strcmp(tok,"ALL_IP_ADDRS")) {
        state->addr = inet_addr("0.0.0.0");
        state->addr_mask = inet_addr("0.0.0.0");
        return 0;
    }

    /* MYHOST_ADDR  keyword */
    if (!strcmp(tok,"MYHOST_ADDR")) {
        struct utsname localname;
        struct hostent *hst;
        
        if(uname(&localname) < 0)
            return 1;

        /* SECURITY HOLE: This is an unsafe way to get the list of
           local addresses.  DNS must NOT be trusted under any circumstances.
           Look at how bind does it, I guess, and maybe use taht.... */
        hst = gethostbyname(localname.nodename);

        if (!hst || !hst->h_addr_list || !*hst->h_addr_list) {
            return 1;
        }

        /* SECURITY HOLE: gethostbyname() returns a pointer to a static
           memory address, and so any information from it has to be copied */
        state->addr = *(unsigned long *) (*hst->h_addr_list);
        state->addr_mask = inet_addr("255.255.255.255");
        return 0;
    }
    

    /* A textual hostname.  Note that this is error-prone, because it
       trusts DNS return values.  It probably should be avoided whereever
       possible.  BUT, I must admit that it _is_ useful.  */
    if (isalpha(*tok)) {
        struct hostent *hst = gethostbyname(tok);

        /* Add a no-warnings flag, and don't print this if set. */
        fprintf(stderr, "Warning: Using DNS lookup for `net':\n"
                        "  DNS should not be trusted, use IP addresses?\n");

        if (!hst || !hst->h_addr_list || !*hst->h_addr_list) {
            return 1;
        }

        state->addr = *(unsigned long *) (*hst->h_addr_list);
        state->addr_mask = inet_addr("255.255.255.255");
        return 0;
    }

    /*dotted quad w/ mask or w/o mask */
   
        PDEBUG("mask:%s",mask);
    if (mask) {
        *mask++ = '\0';
        len = 0;
        sscanf(mask, "%*3d.%*3d.%*3d.%*3d%n", &len);
        if (len < 7)
            return 1;
        state->addr_mask = inet_addr(mask);
    } else
        state->addr_mask = inet_addr("255.255.255.255");

    PDEBUG("1");
    len = 0;
    sscanf(tok, "%*3d.%*3d.%*3d.%*3d%n", &len);

    if (len < 7)
        return 1;

    state->addr = inet_addr(tok);

    return 0;
}

/* given a string parse the port and port mask */
static int parse_port(state_t * state, char *tok)
{
    int len;
    unsigned short p;
    char * mask = strchr(tok,'/');
    state->port_mask = (unsigned short) -1;

    if (mask) {
        *mask++ = '\0';
        len = 0;
        sscanf(mask, "%hd%n", &p, &len);
        if (len == 0) return 1;
        state->port_mask = htons(p);
    } 
        

    len = 0;
    sscanf(tok, "%hd%n", &p, &len);
    if (len == 0) return 1;
    state->port = htons(p);
    
    return 0;
}

static void *init(const char *conf_line)
{
    char * conf_str;
    state_t *state = malloc(sizeof(state_t));
    char * what,*type,*protocol,*addr,*port;
         
    if (state == NULL)
        return (INIT_FAIL);
            
    state->is_unix_domain = 0;

    /* Parse conf_line, fill in state */
    conf_str = strdup(conf_line);

    if (!conf_str) 
        return (INIT_FAIL);

    /* <Julia Childs> First we minse the string 
        into bite sized pieces </Julia Childs>  */
    
    what = strtok(conf_str," \t");
    type = strtok(NULL," \t");
    protocol = strtok(NULL," \t");
    addr = strtok(NULL," \t");
    port = strtok(NULL," \t");

    /* allow or deny? REQUIRED*/

    if (!what) {
        PERROR("Couldn't find allow/deny keyword.");
        goto free_str_exit_failure;
    } else if (!strcmp(what,"allow")) {
        state->what = ALLOW;
    } else if (!strcmp(what,"deny")) {
        state->what = DENY;
    } else {
        PERROR("Couldn't find allow/deny keyword.");
        goto free_str_exit_failure;
    }

    /* What type of socket call are we filtering? REQURED*/

    if (!type) {
        PERROR("couldn't find connect|bind keyword\n");
        goto free_str_exit_failure;
    } else if (!strcmp(type, "connect") ) {
        state->sockcall = CONNECT;
    } else if (!strcmp(type, "bind")) {
        state->sockcall = BIND;
    } else {
        PERROR("couldn't find connect|bind keyword\n");
        goto free_str_exit_failure;
    }

    /* What's the protocol? REQUIRED*/

    if (!protocol) {
        PERROR("couldn't find protocol (tcp|udp|unix-domain|display)");
        goto free_str_exit_failure;
    } else if (!strcasecmp(protocol, "tcp")) {
        state->ptype = TCP;
    } else if (!strcasecmp(protocol, "udp")) {
        state->ptype = UDP;
    } else if (!strcasecmp(protocol, "unix-domain")) {
        state->is_unix_domain = 1;
        state->ptype = TCP;
#ifdef SUPPORT_DISPLAY
    } else if (!strcmp(protocol, "display")) {

        if (parse_display(&state->addr, &state->port)) 
            goto free_str_exit_failure;

        state->ptype = TCP;
        state->addr_mask = -1;
        state->port_mask = -1;

        /* complete display, we are done! */
        goto free_str_exit_success;
#endif
    } else {
        PERROR("couldn't find protocol (tcp|udp|unix-domain|display)");
        goto free_str_exit_failure;
    }

   
   /* snarf an address next REQUIRED*/

    if (!addr) {
        PERROR("Syntax error: couldn't find address\n  (MYHOST_ADDR | ALL_IP_ADDRS | hostname | hostaddress[/addressmask]");
        goto free_str_exit_failure;
    } else if (state->is_unix_domain) {
        if (strlen(addr) >= sizeof(state->path_pattern)) {
            PERROR("addr `%s' too long", addr);
            goto free_str_exit_failure;
        }
        strcpy(state->path_pattern,addr);
        PDEBUG("path %s",addr);
        goto free_str_exit_success;
    } else {
        /*inet socket */ 
        if (parse_address(state,addr)) 
            goto free_str_exit_failure;
    }
        
    /* last snarf port (optional) */

    if (!port) {
        state->port_mask = 0;
        state->port = 0;
    } else {
    
        if (parse_port(state,port)) 
            goto free_str_exit_failure;

    }
    
    free_str_exit_success:
        print_state(state);
        free(conf_str);
        return state;

    free_str_exit_failure:
        free(conf_str);
        return INIT_FAIL;
}

static const syscall_entry entries[] = {
    {SYS_socketcall, FUNC, socketcall_hook},
};

static const int nentries = sizeof(entries) / sizeof(syscall_entry);

void * net_init(const char * conf) { return init(conf); }
int net_num_entries() { return nentries; }
const syscall_entry * net_get_entries() { return entries; }
    

