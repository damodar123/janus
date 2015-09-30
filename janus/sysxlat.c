/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 *
 *
 * Portions of this code have been borrowed from strace, as
 * such the following Copyright also applies.
 */

/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/personality.h>
#include <linux/net.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include "trace.h"
#include "debug.h" 
#include "bsdstring.h" 


struct xlat {
    int num;
    char * name;
};

/*
 * This is a really dirty trick but it should always work.  Traditional
 * Unix says r/w/rw are 0/1/2, so we make them true flags 1/2/3 by
 * adding 1.  Just remember to add 1 to any arg decoded with openmodes.
 * note that modes are called flags in some man pages
 */
struct xlat openmodes[] = {
	{ O_RDWR + 1,	"O_RDWR"	},
	{ O_RDONLY + 1,	"O_RDONLY"	},
	{ O_WRONLY + 1,	"O_WRONLY"	},
	{ O_NONBLOCK,	"O_NONBLOCK"	},
	{ O_APPEND,	"O_APPEND"	},
	{ O_CREAT,	"O_CREAT"	},
	{ O_TRUNC,	"O_TRUNC"	},
	{ O_EXCL,	"O_EXCL"	},
	{ O_NOCTTY,	"O_NOCTTY"	},
#ifdef O_SYNC
	{ O_SYNC,	"O_SYNC"	},
#endif
#ifdef O_ASYNC
	{ O_ASYNC,	"O_ASYNC"	},
#endif
#ifdef O_DSYNC
	{ O_DSYNC,	"O_DSYNC"	},
#endif
#ifdef O_RSYNC
	{ O_RSYNC,	"O_RSYNC"	},
#endif
#ifdef O_NDELAY
	{ O_NDELAY,	"O_NDELAY"	},
#endif
#ifdef O_PRIV
	{ O_PRIV,	"O_PRIV"	},
#endif
#ifdef O_DIRECT
   { O_DIRECT, "O_DIRECT"  },
#endif
#ifdef O_LARGEFILE
   { O_LARGEFILE,  "O_LARGEFILE"   },
#endif
#ifdef O_DIRECTORY
   { O_DIRECTORY,  "O_DIRECTORY"   },
#endif

#ifdef FNDELAY
	{ FNDELAY,	"FNDELAY"	},
#endif
#ifdef FAPPEND
	{ FAPPEND,	"FAPPEND"	},
#endif
#ifdef FMARK
	{ FMARK,	"FMARK"		},
#endif
#ifdef FDEFER
	{ FDEFER,	"FDEFER"	},
#endif
#ifdef FASYNC
	{ FASYNC,	"FASYNC"	},
#endif
#ifdef FSHLOCK
	{ FSHLOCK,	"FSHLOCK"	},
#endif
#ifdef FEXLOCK
	{ FEXLOCK,	"FEXLOCK"	},
#endif
#ifdef FCREAT
	{ FCREAT,	"FCREAT"	},
#endif
#ifdef FTRUNC
	{ FTRUNC,	"FTRUNC"	},
#endif
#ifdef FEXCL
	{ FEXCL,	"FEXCL"		},
#endif
#ifdef FNBIO
	{ FNBIO,	"FNBIO"		},
#endif
#ifdef FSYNC
	{ FSYNC,	"FSYNC"		},
#endif
#ifdef FNOCTTY
	{ FNOCTTY,	"FNOCTTY"	},
#endif
	{ 0,		NULL		},
};

static struct xlat resources[] = {
#ifdef RLIMIT_CPU
	{ RLIMIT_CPU,	"RLIMIT_CPU"	},
#endif
#ifdef RLIMIT_FSIZE
	{ RLIMIT_FSIZE,	"RLIMIT_FSIZE"	},
#endif
#ifdef RLIMIT_DATA
	{ RLIMIT_DATA,	"RLIMIT_DATA"	},
#endif
#ifdef RLIMIT_STACK
	{ RLIMIT_STACK,	"RLIMIT_STACK"	},
#endif
#ifdef RLIMIT_CORE
	{ RLIMIT_CORE,	"RLIMIT_CORE"	},
#endif
#ifdef RLIMIT_RSS
	{ RLIMIT_RSS,	"RLIMIT_RSS"	},
#endif
#ifdef RLIMIT_NOFILE
	{ RLIMIT_NOFILE,"RLIMIT_NOFILE"	},
#endif
#ifdef RLIMIT_VMEM
	{ RLIMIT_VMEM,	"RLIMIT_VMEM"	},
#endif
#ifdef RLIMIT_AS
	{ RLIMIT_AS,	"RLIMIT_AS"	},
#endif
	{ 0,		NULL		},
};


static struct xlat fcntlcmds[] = {
	{ F_DUPFD,	"F_DUPFD"	},
	{ F_GETFD,	"F_GETFD"	},
	{ F_SETFD,	"F_SETFD"	},
	{ F_GETFL,	"F_GETFL"	},
	{ F_SETFL,	"F_SETFL"	},
	{ F_GETLK,	"F_GETLK"	},
	{ F_SETLK,	"F_SETLK"	},
	{ F_SETLKW,	"F_SETLKW"	},
	{ F_GETOWN,	"F_GETOWN"	},
	{ F_SETOWN,	"F_SETOWN"	},
#ifdef F_RSETLK
	{ F_RSETLK,	"F_RSETLK"	},
#endif
#ifdef F_RSETLKW
	{ F_RSETLKW,	"F_RSETLKW"	},
#endif
#ifdef F_RGETLK
	{ F_RGETLK,	"F_RGETLK"	},
#endif
#ifdef F_CNVT
	{ F_CNVT,	"F_CNVT"	},
#endif
	{ 0,		NULL		},
};



static struct xlat personality_tab[] = {
{PER_MASK,   "PER_MASK"},		
{PER_LINUX,   "PER_LINUX"},	
{PER_LINUX_32BIT,   "PER_LINUX_32BIT"},		
{PER_SVR4,   "PER_SVR4"},		
{PER_SVR3,   "PER_SVR3"},	
{PER_SCOSVR3,   "PER_SCOSVR3"},		
{PER_WYSEV386,   "PER_WYSEV386"},		
{PER_ISCR4,   "PER_ISCR4"},		
{PER_BSD,   "PER_BSD"},			
{PER_XENIX,   "PER_XENIX"},		
{PER_LINUX32,   "PER_LINUX32"},	
/* {PER_IRIX32,   "PER_IRIX32"},    */
/* {PER_IRIXN32,   "PER_IRIXN32"},  */
/* {PER_IRIX64,   "PER_IRIX64"},    */
{ 0,            NULL       },
};

static struct xlat sockoptions[] = {
#ifdef SO_PEERCRED
	{ SO_PEERCRED,	"SO_PEERCRED"	},
#endif
#ifdef SO_PASSCRED
	{ SO_PASSCRED,	"SO_PASSCRED"	},
#endif
#ifdef SO_DEBUG
	{ SO_DEBUG,	"SO_DEBUG"	},
#endif
#ifdef SO_REUSEADDR
	{ SO_REUSEADDR,	"SO_REUSEADDR"	},
#endif
#ifdef SO_KEEPALIVE
	{ SO_KEEPALIVE,	"SO_KEEPALIVE"	},
#endif
#ifdef SO_DONTROUTE
	{ SO_DONTROUTE,	"SO_DONTROUTE"	},
#endif
#ifdef SO_BROADCAST
	{ SO_BROADCAST,	"SO_BROADCAST"	},
#endif
#ifdef SO_LINGER
	{ SO_LINGER,	"SO_LINGER"	},
#endif
#ifdef SO_OOBINLINE
	{ SO_OOBINLINE,	"SO_OOBINLINE"	},
#endif
#ifdef SO_TYPE
	{ SO_TYPE,	"SO_TYPE"	},
#endif
#ifdef SO_ERROR
	{ SO_ERROR,	"SO_ERROR"	},
#endif
#ifdef SO_SNDBUF
	{ SO_SNDBUF,	"SO_SNDBUF"	},
#endif
#ifdef SO_RCVBUF
	{ SO_RCVBUF,	"SO_RCVBUF"	},
#endif
#ifdef SO_NO_CHECK
	{ SO_NO_CHECK,	"SO_NO_CHECK"	},
#endif
#ifdef SO_PRIORITY
	{ SO_PRIORITY,	"SO_PRIORITY"	},
#endif
#ifdef SO_ACCEPTCONN
	{ SO_ACCEPTCONN,"SO_ACCEPTCONN"	},
#endif
#ifdef SO_USELOOPBACK
	{ SO_USELOOPBACK,"SO_USELOOPBACK"},
#endif
#ifdef SO_SNDLOWAT
	{ SO_SNDLOWAT,	"SO_SNDLOWAT"	},
#endif
#ifdef SO_RCVLOWAT
	{ SO_RCVLOWAT,	"SO_RCVLOWAT"	},
#endif
#ifdef SO_SNDTIMEO
	{ SO_SNDTIMEO,	"SO_SNDTIMEO"	},
#endif
#ifdef SO_RCVTIMEO
	{ SO_RCVTIMEO,	"SO_RCVTIMEO"	},
#endif
#ifdef SO_BSDCOMPAT
	{ SO_BSDCOMPAT,	"SO_BSDCOMPAT"	},
#endif
#ifdef SO_REUSEPORT
	{ SO_REUSEPORT,	"SO_REUSEPORT"	},
#endif
#ifdef SO_RCVLOWAT
	{ SO_RCVLOWAT, "SO_RCVLOWAT"	},
#endif
#ifdef SO_SNDLOWAT
	{ SO_SNDLOWAT, "SO_SNDLOWAT"	},
#endif
#ifdef SO_RCVTIMEO
	{ SO_RCVTIMEO, "SO_RCVTIMEO"	},
#endif
#ifdef SO_SNDTIMEO
	{ SO_SNDTIMEO, "SO_SNDTIMEO"	},
#endif
	{ 0,		NULL		},
};



static struct xlat addrfams[] = {
{ AF_UNSPEC,    "AF_UNSPEC"     },
{ AF_UNIX,      "AF_UNIX"       },
{ AF_INET,      "AF_INET"       },
{ AF_INET6,     "AF_INET6"      },
{ AF_DECnet,    "AF_DECnet"     },
#ifdef PF_ATMSVC
{ AF_ATMSVC,    "AF_ATMSVC"     },
#endif
{ AF_PACKET,    "AF_PACKET"     },
{ AF_NETLINK,   "AF_NETLINK"    },
#ifdef PF_ISO
{ AF_ISO,       "AF_ISO"        },
#endif
#ifdef PF_IMPLINK
{ AF_IMPLINK,   "AF_IMPLINK"    },
#endif
{ 0,            NULL            },
};


static struct xlat socktypes[] = {
{ SOCK_STREAM,  "SOCK_STREAM"   },
{ SOCK_DGRAM,   "SOCK_DGRAM"    },
#ifdef SOCK_RAW
{ SOCK_RAW, "SOCK_RAW"  },
#endif
#ifdef SOCK_SEQPACKET
{ SOCK_SEQPACKET,"SOCK_SEQPACKET"},
#endif
#ifdef SOCK_RDM
{ SOCK_RDM, "SOCK_RDM"  },
#endif
#ifdef SOCK_PACKET
{ SOCK_PACKET,  "SOCK_PACKET"   },
#endif
{ 0,        NULL        },
};

static struct xlat protocols[] = {
{ IPPROTO_IP,   "IPPROTO_IP"    },
{ IPPROTO_ICMP, "IPPROTO_ICMP"  },
{ IPPROTO_TCP,  "IPPROTO_TCP"   },
{ IPPROTO_UDP,  "IPPROTO_UDP"   },
#ifdef IPPROTO_GGP
{ IPPROTO_GGP,  "IPPROTO_GGP"   },
#endif
#ifdef IPPROTO_EGP
{ IPPROTO_EGP,  "IPPROTO_EGP"   },
#endif
#ifdef IPPROTO_PUP
{ IPPROTO_PUP,  "IPPROTO_PUP"   },
#endif
#ifdef IPPROTO_IDP
{ IPPROTO_IDP,  "IPPROTO_IDP"   },
#endif
#ifdef IPPROTO_IPV6
{ IPPROTO_IPV6, "IPPROTO_IPV6"  },
#endif
#ifdef IPPROTO_ICMPV6
{ IPPROTO_ICMPV6,"IPPROTO_ICMPV6"},
#endif
#ifdef IPPROTO_IGMP
{ IPPROTO_IGMP, "IPPROTO_IGMP"  },
#endif
#ifdef IPPROTO_HELLO
{ IPPROTO_HELLO,"IPPROTO_HELLO" },
#endif
#ifdef IPPROTO_ND
{ IPPROTO_ND,   "IPPROTO_ND"    },
#endif
#ifdef IPPROTO_RAW
{ IPPROTO_RAW,  "IPPROTO_RAW"   },
#endif
#ifdef IPPROTO_MAX
{ IPPROTO_MAX,  "IPPROTO_MAX"   },
#endif
#ifdef IPPROTO_IPIP
{ IPPROTO_IPIP, "IPPROTO_IPIP"  },
#endif
{ 0,        NULL        },
};

static struct xlat socketcall_tab[] = {
 {SYS_SOCKET,"socket"}, 	
 {SYS_BIND,"bind"}, 	
 {SYS_CONNECT,"connect"}, 
 {SYS_LISTEN,"listen"}, 	
 {SYS_ACCEPT,"accept"}, 	
 {SYS_GETSOCKNAME,"getsockname"}, 
 {SYS_GETPEERNAME,"getpeername"}, 
 {SYS_SOCKETPAIR,"socketpair"}, 	
 {SYS_SEND,"send"}, 	
 {SYS_RECV,"recv"}, 
 {SYS_SENDTO,"sendto"}, 	
 {SYS_RECVFROM,"recvfrom"}, 	
 {SYS_SHUTDOWN,"shutdown"}, 	
 {SYS_SETSOCKOPT,"setsockopt"}, 	
 {SYS_GETSOCKOPT,"getsockopt"}, 	
 {SYS_SENDMSG,"sendmsg"}, 	
 {SYS_RECVMSG,"recvmsg"}, 	
 { 0,        NULL        },
};

static struct xlat fcap_event_types[] = 
{ 
  {UNKNOWN,"UNKNOWN"}, 
  {SYSENTRY,"SYSENTRY"}, 
  {SYSEXIT,"SYSEXIT"}, 
  {PROCESSEXIT,"PROCESSEXIT"},
  {0 ,NULL}
}; 

#define OUT_STR_MAX 256

static const char * xlat_num(int num, struct xlat table[])
{
    int i = 0; 

    while ((table[i].name != NULL) && (table[i].num != num))
        i++;
    
    return table[i].name;
}

const char * xlat_socket_domain(int domain)
{
    return xlat_num(domain, addrfams) ? : "Unknown_domain";
}

const char * xlat_socket_type(int type)
{
    return xlat_num(type, socktypes) ? : "Unknown_socktype";
}

const char * xlat_socket_protocol(int protocol)
{
    return xlat_num(protocol, protocols) ? : "Unknown_proto";
}

const char * xlat_socketcall(int command)
{
    return xlat_num(command, socketcall_tab) ? : "Unknown_sockcall";
}

static const char * xlat_sockoptions(int optname)
{
    return  xlat_num(optname, sockoptions) ? : "Unknown_option";
}


const char * xlat_fcap_event(int event)
{
    return  xlat_num(event, fcap_event_types) ? : "Unknown_fcapevent";
}

const char * xlat_personality(int pers)
{
    return  xlat_num(pers, personality_tab) ? : "Unknown_personality";
}

const char * xlat_resources(int type)
{
    return xlat_num(type, resources) ? : "Unknown_resource";
}


static const char * xlat_modes(int mode, struct xlat table[])
{
    static char mode_buff[OUT_STR_MAX];
    int i;
    char * sep;

    sep = "";
    *mode_buff = '\0';

    for (i=0; table[i].name != NULL && mode; i++) {
        if ((mode & (table[i].num)) == table[i].num) {
            strlcat(mode_buff, sep, sizeof(mode_buff));
            strlcat(mode_buff, table[i].name, sizeof(mode_buff));
            mode &= ~table[i].num;
            sep = " | ";
        }
    }

    return mode_buff;
}

const char * xlat_openmodes(int mode)
{
    return xlat_modes(mode + 1, openmodes);
}


char * protectstr_buf(const char *s, char *buf, int buflen)
{
    char *p;
    static char *ok =
        "0123456789 -./_"
        "abcdefghijklmonpqrstuvwxyz"
	    "ABCDEFGHIJKLMONPQRSTUVWXYZ";

    assert(s);

    /* Other code assumes that these chars are not ok. */
    assert(!strpbrk(ok, "<>[]{}()'\"\n\r"));

    for (p=buf; *s && p < buf+buflen-32; s++) {
	    /* Don't want to use isalpha(), because it depends on locale (argh!) */
        if (strchr(ok, *s)) {
	        *p++ = *s;
	    } else {
	        char expanded[16];
	        expanded[0] = '\0';
	        snprintf(expanded, sizeof(expanded), "\\x%2.2X", (unsigned int)*s);
	        if (strlen(expanded) > 4)
	            expanded[0] = '\0';
            strcpy(p, expanded);
	        p += strlen(expanded);
	    }
    }
    if (*s) {
	    char *xtra = "... [truncated]";
	    assert(p < buf+buflen-strlen(xtra)-1);
        strcpy(p, xtra);
    } else
        *p = '\0';
    return buf;
}
char * protectstr(const char *s)
{
    static char buf[OUT_STR_MAX];
    return protectstr_buf(s, buf, sizeof(buf));
}

/* modified from steven's */

const char * xlat_sockaddr(const struct sockaddr *sa, int salen)
{
    char str[OUT_STR_MAX];		/* Unix domain is largest */
    static char buf[OUT_STR_MAX];

    str[0] = '\0';
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sinp = (struct sockaddr_in *) sa;
		const char *rv;

        if (salen != sizeof(struct sockaddr_in))
            return "BADLENGTH_inet_sockaddr";
		rv = inet_ntop(AF_INET, &sinp->sin_addr, buf, sizeof(buf)-8);
		if (!rv)
			return "BAD_inet_sockaddr";
		if (ntohs(sinp->sin_port) != 0) {
			snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf),
			     ":%d", ntohs(sinp->sin_port));
		}
		return buf;
	}

	case AF_UNIX: {
        static char result[OUT_STR_MAX];
		struct sockaddr_un	*unp = (struct sockaddr_un *) sa;

        if (salen > sizeof(struct sockaddr_un))
            return "BADLENGTH_unix_sockaddr";
		/* OK to have no pathname bound to the socket: happens on
		   every connect() unless client calls bind() first. */
		if (unp->sun_path[0] == '\0')
			return "AF_UNIX socket (no pathname bound)";

		protectstr_buf(unp->sun_path, buf, sizeof(buf));
        snprintf(result,sizeof(result),"\"%s\"",buf);
        return result;
	}


	default:
        if (salen < sizeof(struct sockaddr_in))
            return "BADLENGTH_unknown_sockaddr";
		snprintf(buf, sizeof(buf),
			"unknown socket (AF_xxx: %d, len %d)",
			 sa->sa_family, salen);
		return buf;
	}
    return "BAD_sockaddr";
}



#define LAST_CALL 254

typedef struct {
	int nargs;
	int (*xlat_call) (const char *name, int nargs, prstat_t prstat,
					  char *call, int size);
	int num;
	const char *name;
} call_xlat;

static call_xlat syscall_xlat_tab[];

int xlat_callname(const char * name)
{
    int i;

    for (i=0; i <= LAST_CALL; i++)
        if (syscall_xlat_tab[i].name && !strcmp(syscall_xlat_tab[i].name, name))
	        return i;

    return -1;
}

const char * xlat_callnum(int num)
{
     const char *p;
     if (num < 0 || num > LAST_CALL)
        return "Syscall out of range";
    
     p = syscall_xlat_tab[num].name;
     assert(p);
     return p;
}

void xlat_system_call(char * call, int size, prstat_t prstat)
{
    call_xlat ce;
    int rv;

    if (prstat.syscall < 0 || prstat.syscall > LAST_CALL) {
        snprintf(call, size, "Syscall %d out of range", prstat.syscall);
        return;
    }
   
    ce = syscall_xlat_tab[prstat.syscall];

    if (prstat.why != SYSENTRY && prstat.why != SYSEXIT) {
        snprintf(call, size, "Not a syscall (%s)", xlat_fcap_event(prstat.why));
        return;
    }

    rv = ce.xlat_call(ce.name, ce.nargs, prstat, call, size);
    assert(!rv);

    if (prstat.why == SYSEXIT)
        snprintf(call + strlen(call), size - strlen(call), 
            " = %d", prstat.rv);
} 
        


#define FORMAT_CALL_ARGS \
    const char *name, int nargs, prstat_t prstat, char *call, int size


/* In order to simplify printing out all sorts of calls I 
   have classified many of them into "forms". */

/* basic forms */
static int no_args(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s()", name);
    return 0;
}

static int no_notable_args(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(...)", name);
    return 0;
}

static int not_supported(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(...printing args not supported yet...)", name);
    return 0;
}

static int not_implemented(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(...linux does not implement this call...)", name);
    return 0;
}

static int obsolete_call(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(...this call is obsolete...)", name);
    return 0;
}



static int invalid_args(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(invalid args...)", name);
    return 0;
}

/* int forms */
static int one_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d)", name, (int)prstat.args[0]);
    return 0;
}

static int two_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d, %d)",
        name, (int) prstat.args[0], (int)prstat.args[1]);
    return 0;
}

static int three_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d, %d, %d)", name,
            (int) prstat.args[0], 
            (int)prstat.args[1], 
            (int)prstat.args[2]);

    return 0;
}

static int four_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d, %d, %d, %d)", name,
            (int) prstat.args[0], 
            (int)prstat.args[1], 
            (int)prstat.args[2],
            (int)prstat.args[3]);

    return 0;
}





static int first_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d, ...)", name, (int)prstat.args[0]);
    return 0;
}

static int first_two_int(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%d, %d, ...)",
        name, (int) prstat.args[0], (int)prstat.args[1]);
    return 0;
}

#define FCAP_PATH_MAX ((PATH_MAX * 3) + 20)

static int fetch_path(int arg, char *buf, int bufsiz, const pcb_t *pcb)
{
    char path[PATH_MAX];
    char path_absolute_follow[PATH_MAX];
    char path_absolute_nofollow[PATH_MAX];

    if (fetcharg(pcb, arg, path, sizeof(path), TYPE_PATH))
        return -1;
   
    strlcpy(buf, "\"", bufsiz);
    protectstr_buf(path, buf+1, bufsiz-2);
    strlcat(buf, "\"", bufsiz);

    if (fetcharg(pcb, arg, path_absolute_follow,
            sizeof(path_absolute_follow), TYPE_PATH_FOLLOW))
        return -1;

    if (fetcharg(pcb, arg, path_absolute_nofollow,
            sizeof(path_absolute_nofollow), TYPE_PATH_NOFOLLOW))
        return -1;
    
    /* If this is a symlink, then show what the symlink resolves to. */
    if (strcmp(path_absolute_nofollow, path_absolute_follow)) {
        char tmppath[2*PATH_MAX + 80];
        char protected[PATH_MAX];
        strlcpy(tmppath, buf, sizeof(tmppath));
        strlcat(tmppath, " [symlink -> \"", sizeof(tmppath));
        protectstr_buf(path_absolute_follow, protected, sizeof(protected));
        strlcat(tmppath, protected, sizeof(tmppath));
        strlcat(tmppath, "\"]", sizeof(tmppath));
        strlcpy(buf, tmppath, bufsiz);
    }

    return 0;
}

/* A shortcut */
#define FETCH_PATH(arg, buf) \
    do { \
        if (fetch_path(arg, buf, sizeof(buf), prstat.pcb)) \
            return invalid_args(name, nargs, prstat, call, size); \
    } while(0)



/* Path forms */
static int path_and_flags(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];

    FETCH_PATH(0, path);

    snprintf(call, size, "%s(%s, %#lo)", name, path, prstat.args[1]);
    return 0;
}

static int one_path(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];

    FETCH_PATH(0, path);

    snprintf(call, size, "%s(%s)", name, path);
    return 0;
}

static int two_path(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];
    char path2[FCAP_PATH_MAX];

    FETCH_PATH(0, path);  
    FETCH_PATH(1, path2);  
   
    snprintf(call, size, "%s(%s, %s)", name, path, path2);
    return 0;
}

static int first_path(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];

    FETCH_PATH(0, path);  

    snprintf(call, size, "%s(%s, ...)", name, path);
    return 0;
}

static int first_two_path(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];
    char path2[FCAP_PATH_MAX];
    
    FETCH_PATH(0, path);  
    FETCH_PATH(1, path2);  

    snprintf(call, size, "%s(%s, %s, ...)", name, path, path2);
    return 0;
}



/* system call specific */
static int sys_xlat_personality(FORMAT_CALL_ARGS)
{
	snprintf(call, size, "%s(%s)", name, xlat_personality(prstat.args[0]));
    return 0;
}

/* note that the names of modes and flags is reversed here compared to
the man page */
static int sys_xlat_open(FORMAT_CALL_ARGS)
{
    char path[FCAP_PATH_MAX];
    char * modes = strdup(xlat_openmodes(prstat.args[1]));

    FETCH_PATH(0, path);

    if (prstat.args[1] & O_CREAT)
        snprintf(call, size, "%s(%s, %s, %#lo)", name, path, modes,
             prstat.args[2]);
    else 
        snprintf(call, size, "%s(%s, %s)", name, path, modes);
    
    free(modes);
    return 0;
}

static int sys_xlat_fcntl(FORMAT_CALL_ARGS)
{
    const char * cmd;
    
    cmd = xlat_num(prstat.args[1], fcntlcmds) ? : "unknown_cmd";
	snprintf(call, size, "%s(%d, %s, %ld)",
        name, (int)prstat.args[0], cmd, prstat.args[2]);
    return 0;
}

static int sys_xlat_setgroups(FORMAT_CALL_ARGS)
{
    int i;
    int num_groups = prstat.args[0];
    janus_gid_t groups[NGROUPS_MAX];
    char group_list[OUT_STR_MAX];
    char * sep = "", *p, *end;

    if (num_groups > NGROUPS_MAX || num_groups < 0)
        return invalid_args(name, nargs, prstat, call, size); 

    if (fetcharg(prstat.pcb, 1, groups, num_groups * sizeof(janus_gid_t), TYPE_POINTER)) 
        return invalid_args(name, nargs, prstat, call, size); 

    p = group_list;
    end = group_list + sizeof(group_list);
    for (i = 0; i < num_groups; i++) {
        snprintf(p, end-p, "%s%d", sep, groups[i]); 
        sep = ",";
        p += strlen(p);
    }

    snprintf(call, size, "%s(%d, [%s])", name, num_groups, group_list);
    return 0;
}



/* I hate the socket call interface */

 /* sockaddr_un is the largest type of sockaddr possible */
typedef struct sockaddr_un sockaddr_unknown;


static int sys_xlat_socketcall(FORMAT_CALL_ARGS)
{
    const char * command = xlat_socketcall(prstat.args[0]);

    switch (prstat.args[0]) {
    case SYS_SOCKETPAIR:
    case SYS_SENDMSG:   
    case SYS_RECVMSG:
    case SYS_RECVFROM:
    case SYS_GETSOCKNAME:
    case SYS_GETPEERNAME:
    case SYS_SEND:
    case SYS_RECV:
    case SYS_GETSOCKOPT:
    case SYS_LISTEN:
    case SYS_ACCEPT:
    case SYS_SHUTDOWN:
        /* These are not printed in detail yet */
#if notyet
    {
        int first_arg;

        if (fetcharg(prstat.pcb, 0, &first_arg, sizeof(int), TYPE_SCALAR))
            return invalid_args(command, nargs, prstat, call, size); 

        snprintf(call, size, "%s(%d, ...)", command, first_arg);
        break;
    }
#else
        return not_supported(command, nargs, prstat, call, size); 
#endif

    case SYS_SETSOCKOPT: {
        int fd, optname, level;

        if (fetcharg(prstat.pcb, 0, &fd, sizeof(int), TYPE_SCALAR)    ||
            fetcharg(prstat.pcb, 1, &level, sizeof(int), TYPE_SCALAR) ||   
            fetcharg(prstat.pcb, 2, &optname, sizeof(int), TYPE_SCALAR)) 
            return  invalid_args(command, nargs, prstat, call, size); 
        
        snprintf(call, size, "%s(%d, %d, %s, ...)", command, fd, level,
            xlat_sockoptions(optname));
        break;
    }

    case SYS_SENDTO: {
        int fd, addrlen, type;
        sockaddr_unknown sa;

        if (fetcharg(prstat.pcb, 0, &fd, sizeof(int), TYPE_SCALAR)      || 
            fetcharg(prstat.pcb, 5, &addrlen, sizeof(int), TYPE_SCALAR) || 
            fetcharg(prstat.pcb, 4, &sa, addrlen, TYPE_SOCKADDR)         || 
            fetch_sockettype(prstat.pcb, fd, &type))
                return invalid_args(command, nargs, prstat, call, size); 

        snprintf(call, size, "%s(%d, ..., %s, %d) => %s", command, fd,
            xlat_sockaddr((struct sockaddr *)&sa, addrlen), addrlen,
            xlat_socket_type(type));
        break;
    }

    case SYS_CONNECT:
    case SYS_BIND: {
        int fd, addrlen, type;
        sockaddr_unknown sa;

        if (fetcharg(prstat.pcb, 0, &fd, sizeof(int), TYPE_SCALAR) ||
            fetcharg(prstat.pcb, 2, &addrlen, sizeof(int), TYPE_SCALAR) ||
            fetcharg(prstat.pcb, 1, &sa, addrlen, TYPE_SOCKADDR)          ||
            fetch_sockettype(prstat.pcb, fd, &type))
            return invalid_args(command, nargs, prstat, call, size); 


        snprintf(call, size, "%s(%d, %s, %d) => %s", command, fd,
            xlat_sockaddr((struct sockaddr *)&sa, addrlen), addrlen,
            xlat_socket_type(type));
        break; 
    }

    case SYS_SOCKET: {
        int domain;
        int type;
        int protocol;

        if (fetcharg(prstat.pcb, 0, &domain, sizeof(int), TYPE_SCALAR) ||    
            fetcharg(prstat.pcb, 1, &type, sizeof(int), TYPE_SCALAR)    ||
            fetcharg(prstat.pcb, 2, &protocol, sizeof(int), TYPE_SCALAR))  
                 return invalid_args(command, nargs, prstat, call, size); 

        snprintf(call, size, "%s(%s, %s, %s)", command,
            xlat_socket_domain(domain),
            xlat_socket_type(type), 
            xlat_socket_protocol(protocol));
        break;
    }

    default:
        snprintf(call, size, "Unknown socketcall call-type");
    }

    return 0;
}

static int sys_xlat_kill(FORMAT_CALL_ARGS)
{
    snprintf(call, size, "%s(%d, %s)",
        name, (int)prstat.args[0], strsignal(prstat.args[1]));
    return 0;
}

static int sys_xlat_setrlimit(FORMAT_CALL_ARGS)
{
    snprintf(call, size, "%s(%s, ...)",
        name, xlat_resources(prstat.args[0]));
    return 0;
}


static int sys_xlat_chown(FORMAT_CALL_ARGS)
{
    struct passwd * pw = getpwuid(prstat.args[1]);
    struct group * gr = getgrgid(prstat.args[2]);

    char * uname = "user lookup failed";
    char * group = "group lookup failed";


    if (pw) 
        uname = pw->pw_name;
    
    if (gr) 
        group = gr->gr_name;

    if (prstat.syscall == SYS_fchown) 
        snprintf(call, size, "%s(%d, %s, %s)",
            name, (int) prstat.args[0], uname, group);
    else {
        char path[FCAP_PATH_MAX];
        FETCH_PATH(0, path);
        snprintf(call, size, "%s(%s, %s, %s)", name, path, uname, group);
    }

    return 0;

}    

static int sys_xlat_umask(FORMAT_CALL_ARGS)
{
    snprintf(call, size, "%s(%#lo)", name,prstat.args[0]);
    return 0;
}

static int sys_xlat_fchmod(FORMAT_CALL_ARGS)
{
    snprintf(call, size, "%s(%d, %#lo)",
        name, (int)prstat.args[0], prstat.args[1]);
    return 0;
}
    
static call_xlat syscall_xlat_tab[LAST_CALL+2] = {
	{0, no_args, 0, "setup"},	/* 0 */
	{1, one_int, SYS_exit, "_exit"},	/* 1 */
	{0, no_args, SYS_fork, "fork"},	/* 2 */
	{3, first_int, SYS_read, "read"},	/* 3 */
	{3, first_int, SYS_write, "write"},	/* 4 */
	{3, sys_xlat_open, SYS_open, "open"},	/* 5 */
	{1, one_int, SYS_close, "close"},	/* 6 */
	{3, first_int, SYS_waitpid, "waitpid"},	/* 7 */
	{2, path_and_flags, SYS_creat, "creat"},	/* 8 */
	{2, two_path, SYS_link, "link"},	/* 9 */
	{1, one_path, SYS_unlink, "unlink"},	/* 10 */
	{3, first_path, SYS_execve, "execve"},	/* 11 */
	{1, one_path, SYS_chdir, "chdir"},	/* 12 */
	{1, no_notable_args, SYS_time, "time"},	/* 13 */
	{3, first_path, SYS_mknod, "mknod"},	/* 14 */
	{2, path_and_flags, SYS_chmod, "chmod"},	/* 15 */
	{3, sys_xlat_chown, SYS_chown, "lchown"},	/* 16 */        
	{0, not_implemented, SYS_break, "break"},	/* 17 */
	{2, obsolete_call, SYS_oldstat, "oldstat"},	/* 18 */
	{3, three_int, SYS_lseek, "lseek"},	/* 19 */
	{0, no_args, SYS_getpid, "getpid"},	/* 20 */
	{5, not_supported, SYS_mount, "mount"},	/* 21 */
	{1, one_path, SYS_umount, "oldumount"},	/* 22 */
	{1, one_int, SYS_setuid, "setuid"},	/* 23 */
	{0, no_args, SYS_getuid, "getuid"},	/* 24 */
	{1, no_notable_args, SYS_stime, "stime"},	/* 25 */
	{4, four_int, SYS_ptrace, "ptrace"},	/* 26 */
	{1, one_int, SYS_alarm, "alarm"},	/* 27 */
	{2, not_supported, SYS_oldfstat, "oldfstat"},	/* 28 */
	{0, no_args, SYS_pause, "pause"},	/* 29 */
	{2, first_path, SYS_utime, "utime"},	/* 30 */
	{2, not_implemented, SYS_stty, "stty"},	/* 31 */
	{2, not_implemented, SYS_gtty, "gtty"},	/* 32 */
	{2, path_and_flags, SYS_access, "access"},	/* 33 */
	{1, one_int, SYS_nice, "nice"},	/* 34 */
	{0, no_notable_args, SYS_ftime, "ftime"},	/* 35 */
	{0, no_args, SYS_sync, "sync"},	/* 36 */
	{2, sys_xlat_kill, SYS_kill, "kill"},	/* 37 */
	{2, two_path, SYS_rename, "rename"},	/* 38 */
	{2, path_and_flags, SYS_mkdir, "mkdir"},	/* 39 */
	{1, one_path, SYS_rmdir, "rmdir"},	/* 40 */
	{1, one_int, SYS_dup, "dup"},		/* 41 */
	{1, no_notable_args, SYS_pipe, "pipe"},	/* 42 */
	{1, no_notable_args, SYS_times, "times"},	/* 43 */
	{0, not_supported, SYS_prof, "prof"},	/* 44 */
	{1, one_int, SYS_brk, "brk"},		/* 45 */
	{1, one_int, SYS_setgid, "setgid"},	/* 46 */
	{0, no_args, SYS_getgid, "getgid"},	/* 47 */
	{3, not_supported, SYS_signal, "signal"},	/* 48 */
	{0, no_args, SYS_geteuid, "geteuid"},	/* 49 */
	{0, no_args, SYS_getegid, "getegid"},	/* 50 */
	{1, not_supported, SYS_acct, "acct"},	/* 51 */
	{2, not_supported, SYS_umount2, "umount"},	/* 52 */
	{0, not_supported, SYS_lock, "lock"},	/* 53 */
	{3, first_two_int, SYS_ioctl, "ioctl"},	/* 54 */
	{3, sys_xlat_fcntl, SYS_fcntl, "fcntl"},	/* 55 */
	{0, not_implemented, SYS_mpx, "mpx"},	/* 56 */
	{2, two_int, SYS_setpgid, "setpgid"},	/* 57 */
	{2, obsolete_call, SYS_ulimit, "ulimit"},	/* 58 */
	{1, obsolete_call, SYS_oldolduname, "oldolduname"},	/* 59 */
	{1, sys_xlat_umask, SYS_umask, "umask"},	/* 60 */
	{1, one_path, SYS_chroot, "chroot"},	/* 61 */
	{2, first_int, SYS_ustat, "ustat"},	/* 62 */
	{2, two_int, SYS_dup2, "dup2"},	/* 63 */
	{0, no_args, SYS_getppid, "getppid"},	/* 64 */
	{0, no_args, SYS_getpgrp, "getpgrp"},	/* 65 */
	{0, no_args, SYS_setsid, "setsid"},	/* 66 */
	{3, not_supported, SYS_sigaction, "sigaction"},	/* 67 */
	{0, not_supported, SYS_sgetmask, "siggetmask"},	/* 68 */
	{1, not_supported, SYS_ssetmask, "sigsetmask"},	/* 69 */
	{2, two_int, SYS_setreuid, "setreuid"},	/* 70 */
	{2, two_int, SYS_setregid, "setregid"},	/* 71 */
	{3, not_supported, SYS_sigsuspend, "sigsuspend"},	/* 72 */
	{1, not_supported, SYS_sigpending, "sigpending"},	/* 73 */
	{2, not_supported, SYS_sethostname, "sethostname"},	/* 74 */
	{2, sys_xlat_setrlimit, SYS_setrlimit, "setrlimit"},	/* 75 */
	{2, not_supported, SYS_getrlimit, "getrlimit"},	/* 76 */
	{2, not_supported, SYS_getrusage, "getrusage"},	/* 77 */
	{2, no_notable_args, SYS_gettimeofday, "gettimeofday"},	/* 78 */
	{2, not_supported, SYS_settimeofday, "settimeofday"},	/* 79 */
	{2, no_notable_args, SYS_getgroups, "getgroups"},	/* 80 */
	{2, sys_xlat_setgroups, SYS_setgroups, "setgroups"},	/* 81 */
	{1, not_supported, SYS_select, "oldselect"},	/* 82 */
	{2, two_path, SYS_symlink, "symlink"},	/* 83 */
	{2, not_supported, SYS_oldlstat, "oldlstat"},	/* 84 */
	{3, first_two_path, SYS_readlink, "readlink"},	/* 85 */
	{1, not_supported, SYS_uselib, "uselib"},	/* 86 */
	{1, not_supported, SYS_swapon, "swapon"},	/* 87 */
	{3, not_supported, SYS_reboot, "reboot"},	/* 88 */
	{3, not_supported, SYS_readdir, "readdir"},	/* 89 */
	{6, not_supported, SYS_mmap, "mmap"},	/* 90 */
	{2, not_supported, SYS_munmap, "munmap"},	/* 91 */
	{2, not_supported, SYS_truncate, "truncate"},	/* 92 */
	{2, not_supported, SYS_ftruncate, "ftruncate"},	/* 93 */
	{2, sys_xlat_fchmod, SYS_fchmod, "fchmod"},	/* 94 */
	{3, sys_xlat_chown, SYS_fchown, "fchown"},	/* 95 */
	{2, two_int, SYS_getpriority, "getpriority"},	/* 96 */
	{3, three_int, SYS_setpriority, "setpriority"},	/* 97 */
	{4, not_supported, SYS_profil, "profil"},	/* 98 */
	{2, first_path, SYS_statfs, "statfs"},	/* 99 */
	{2, first_int, SYS_fstatfs, "fstatfs"},	/* 100 */
	{3, not_supported, SYS_ioperm, "ioperm"},	/* 101 */
	{2, sys_xlat_socketcall, SYS_socketcall, "socketcall"},	/* 102 */
	{3, not_supported, SYS_syslog, "syslog"},	/* 103 */
	{3, not_supported, SYS_setitimer, "setitimer"},	/* 104 */
	{2, not_supported, SYS_getitimer, "getitimer"},	/* 105 */
	{2, first_path, SYS_stat, "stat"},	/* 106 */
	{2, first_path, SYS_lstat, "lstat"},	/* 107 */
	{2, first_int, SYS_fstat, "fstat"},	/* 108 */
	{1, not_supported, SYS_olduname, "olduname"},	/* 109 */
	{1, not_supported, SYS_iopl, "iopl"},	/* 110 */
	{0, not_supported, SYS_vhangup, "vhangup"},	/* 111 */
	{0, not_supported, SYS_idle, "idle"},	/* 112 */
	{1, not_supported, SYS_vm86old, "vm86old"},	/* 113 */
	{4, not_supported, SYS_wait4, "wait4"},	/* 114 */
	{1, not_supported, SYS_swapoff, "swapoff"},	/* 115 */
	{1, not_supported, SYS_sysinfo, "sysinfo"},	/* 116 */
	{5, not_supported, SYS_ipc, "ipc"},		/* 117 */
	{1, not_supported, SYS_fsync, "fsync"},	/* 118 */
	{1, not_supported, SYS_sigreturn, "sigreturn"},	/* 119 */
	{2, not_supported, SYS_clone, "clone"},	/* 120 */
	{2, not_supported, SYS_setdomainname, "setdomainname"},	/* 121 */
	{1, not_supported, SYS_uname, "uname"},	/* 122 */
	{3, not_supported, SYS_modify_ldt, "modify_ldt"},	/* 123 */
	{1, not_supported, SYS_adjtimex, "adjtimex"},	/* 124 */
	{3, not_supported, SYS_mprotect, "mprotect"},	/* 125 */
	{3, not_supported, SYS_sigprocmask, "sigprocmask"},	/* 126 */
	{2, not_supported, SYS_create_module, "create_module"},	/* 127 */
	{2, not_supported, SYS_init_module, "init_module"},	/* 128 */
	{1, not_supported, SYS_delete_module, "delete_module"},	/* 129 */
	{1, not_supported, SYS_get_kernel_syms, "get_kernel_syms"},	/* 130 */
	{4, not_supported, SYS_quotactl, "quotactl"},	/* 131 */
	{1, no_args, SYS_getpgid, "getpgid"},	/* 132 */
	{1, one_int, SYS_fchdir, "fchdir"},	/* 133 */
	{0, not_supported, SYS_bdflush, "bdflush"},	/* 134 */
	{3, not_supported, SYS_sysfs, "sysfs"},	/* 135 */
	{1, sys_xlat_personality, SYS_personality, "personality"},	/* 136 */
	{5, not_supported, SYS_afs_syscall, "afs_syscall"},	/* 137 */
	{1, one_int, SYS_setfsuid, "setfsuid"},	/* 138 */
	{1, one_int, SYS_setfsgid, "setfsgid"},	/* 139 */
	{5, not_supported, SYS__llseek, "_llseek"},	/* 140 */
	{3, not_supported, SYS_getdents, "getdents"},	/* 141 */
	{5, not_supported, SYS__newselect, "select"},	/* 142 */
	{2, not_supported, SYS_flock, "flock"},	/* 143 */
	{3, not_supported, SYS_msync, "msync"},	/* 144 */
	{3, first_int, SYS_readv, "readv"},	/* 145 */
	{3, first_int, SYS_writev, "writev"},	/* 146 */
	{1, one_int, SYS_getsid, "getsid"},	/* 147 */
	{1, not_supported, SYS_fdatasync, "fdatasync"},	/* 148 */
	{1, not_supported, SYS__sysctl, "_sysctl"},	/* 149 */
	{1, not_supported, SYS_mlock, "mlock"},	/* 150 */
	{2, not_supported, SYS_munlock, "munlock"},	/* 151 */
	{2, not_supported, SYS_mlockall, "mlockall"},	/* 152 */
	{1, not_supported, SYS_munlockall, "munlockall"},	/* 153 */
	{0, not_supported, SYS_sched_setparam, "sched_setparam"},	/* 154 */
	{2, not_supported, SYS_sched_getparam, "sched_getparam"},	/* 155 */
	{3, not_supported, SYS_sched_setscheduler, "sched_setscheduler"},	/* 156 */
	{1, not_supported, SYS_sched_getscheduler, "sched_getscheduler"},	/* 157 */
	{0, not_supported, SYS_sched_yield, "sched_yield"},	/* 158 */
	{1, not_supported, SYS_sched_get_priority_max, "sched_get_priority_max"},	/* 159 */
	{1, not_supported, SYS_sched_get_priority_min, "sched_get_priority_min"},	/* 160 */
	{2, not_supported, SYS_sched_rr_get_interval, "sched_rr_get_interval"},	/* 161 */
	{2, not_supported, SYS_nanosleep, "nanosleep"},	/* 162 */
	{4, not_supported, SYS_mremap, "mremap"},	/* 163 */
	{3, three_int, SYS_setresuid, "setresuid"},	/* 164 */
	{3, not_supported, SYS_getresuid, "getresuid"},	/* 165 */
	{5, not_supported, 166, "vm86"},	/* 166 */
	{5, not_supported, SYS_query_module, "query_module"},	/* 167 */
	{3, not_supported, SYS_poll, "poll"},	/* 168 */
	{3, not_supported, SYS_nfsservctl, "nfsservctl"},	/* 169 */
	{3, three_int, SYS_setresgid, "setresgid"},	/* 170 */
	{3, not_supported, SYS_getresgid, "getresgid"},	/* 171 */
	{5, not_supported, 172, "prctl"},	/* 172 */
	{1, not_supported, SYS_rt_sigreturn, "rt_sigreturn"},	/* 173 */
	{4, not_supported, SYS_rt_sigaction, "rt_sigaction"},	/* 174 */
	{4, not_supported, SYS_rt_sigprocmask, "rt_sigprocmask"},	/* 175 */
	{2, not_supported, SYS_rt_sigpending, "rt_sigpending"},	/* 176 */
	{4, not_supported, SYS_rt_sigtimedwait, "rt_sigtimedwait"},	/* 177 */
	{3, not_supported, SYS_rt_sigqueueinfo, "rt_sigqueueinfo"},	/* 178 */
	{2, not_supported, SYS_rt_sigsuspend, "rt_sigsuspend"},	/* 179 */
	{5, first_int, SYS_pread, "pread"},	/* 180 */
	{5, first_int, SYS_pwrite, "pwrite"},	/* 181 */
	{3, sys_xlat_chown, SYS_chown, "chown"},	/* 182 */
	{2, not_supported, SYS_getcwd, "getcwd"},	/* 183 */
	{2, not_supported, SYS_capget, "capget"},	/* 184 */
	{2, not_supported, SYS_capset, "capset"},	/* 185 */
	{2, not_supported, SYS_sigaltstack, "sigaltstack"},	/* 186 */
	{4, first_int, SYS_sendfile, "sendfile"},	/* 187 */
	{0, not_supported, 188, "SYS_188"},	/* 188 */
	{0, not_supported, 189, "SYS_189"},	/* 189 */
	{0, no_args, SYS_vfork, "vfork"},	/* 190 */
	{0, not_supported, 191, "SYS_191"},
	{0, not_supported, 192, "SYS_192"},
	{0, not_supported, 193, "SYS_193"},
	{0, not_supported, 194, "SYS_194"},
	{0, not_supported, 195, "SYS_195"},
	{0, not_supported, 196, "SYS_196"},
	{0, not_supported, 197, "SYS_197"},
	{0, not_supported, 198, "SYS_198"},
	{0, not_supported, 199, "SYS_199"},
	{0, not_supported, 200, "SYS_200"},
	{0, not_supported, 201, "SYS_201"},
	{0, not_supported, 202, "SYS_202"},
	{0, not_supported, 203, "SYS_203"},
	{0, not_supported, 204, "SYS_204"},
	{0, not_supported, 205, "SYS_205"},
	{0, not_supported, 206, "SYS_206"},
	{0, not_supported, 207, "SYS_207"},
	{0, not_supported, 208, "SYS_208"},
	{0, not_supported, 209, "SYS_209"},
	{0, not_supported, 210, "SYS_210"},
	{0, not_supported, 211, "SYS_211"},
	{0, not_supported, 212, "SYS_212"},
	{0, not_supported, 213, "SYS_213"},
	{0, not_supported, 214, "SYS_214"},
	{0, not_supported, 215, "SYS_215"},
	{0, not_supported, 216, "SYS_216"},
	{0, not_supported, 217, "SYS_217"},
	{0, not_supported, 218, "SYS_218"},
	{0, not_supported, 219, "SYS_219"},
	{0, not_supported, 220, "SYS_220"},
	{0, not_supported, 221, "SYS_221"},
	{0, not_supported, 222, "SYS_222"},
	{0, not_supported, 223, "SYS_223"},
	{0, not_supported, 224, "SYS_224"},
	{0, not_supported, 225, "SYS_225"},
	{0, not_supported, 226, "SYS_226"},
	{0, not_supported, 227, "SYS_227"},
	{0, not_supported, 228, "SYS_228"},
	{0, not_supported, 229, "SYS_229"},
	{0, not_supported, 230, "SYS_230"},
	{0, not_supported, 231, "SYS_231"},
	{0, not_supported, 232, "SYS_232"},
	{0, not_supported, 233, "SYS_233"},
	{0, not_supported, 234, "SYS_234"},
	{0, not_supported, 235, "SYS_235"},
	{0, not_supported, 236, "SYS_236"},
	{0, not_supported, 237, "SYS_237"},
	{0, not_supported, 238, "SYS_238"},
	{0, not_supported, 239, "SYS_239"},
	{0, not_supported, 240, "SYS_240"},
	{0, not_supported, 241, "SYS_241"},
	{0, not_supported, 242, "SYS_242"},
	{0, not_supported, 243, "SYS_243"},
	{0, not_supported, 244, "SYS_244"},
	{0, not_supported, 245, "SYS_245"},
	{0, not_supported, 246, "SYS_246"},
	{0, not_supported, 247, "SYS_247"},
	{0, not_supported, 248, "SYS_248"},
	{0, not_supported, 249, "SYS_249"},
	{0, not_supported, 250, "SYS_250"},
	{0, not_supported, 251, "SYS_251"},
	{0, not_supported, 252, "SYS_252"},
	{0, not_supported, 253, "SYS_253"},
	{0, not_supported, 254, "SYS_254"},
	{0, NULL, 0, NULL},
};
