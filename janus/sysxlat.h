/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef SYSXLAT_H
#define SYSXLAT_H

#include <sys/socket.h>
#include "trace.h"

/* Promise: none of the following num->name translators will return NULL. */

/* Warning: Results are often a pointer into a static buffer!
   Make sure to strdup() the result if you want to modify it,
   or if you want to call any of these functions again before
   using the result. */

/* Translate systemcall number into a readable string. */
const char * xlat_callnum(int num);

/* Translate system call name into its number, or -1 upon failure. */
int xlat_callname(const char *);

/* Translate socketcall numbers (bind/connect etc.) */
const char * xlat_socketcall(int);

/* translate socket arguments */
const char * xlat_socket_domain(int domain);
const char * xlat_socket_type(int type);
const char * xlat_socket_protocol(int protocol);

/* Translate a sockaddr into a printable format.
   The result is a pointer into a static buffer -- make sure to
   strdup() it if you want to modify the result, or if you want
   to call xlat_sockaddr() again before using the first result! */
const char * xlat_sockaddr(const struct sockaddr *sa, int salen);

/* Translate fcap events */
const char * xlat_fcap_event(int event);

/* Translate the mode argument to open(), creat(), etc. */
const char * xlat_openmodes(int mode);


/* Escape any characters that are dangerous to display.
   The result is a pointer into a static buffer. */
char * protectstr(const char *s);

/* Translates the system call event referred to by p into a string,
   and stores the result into 'dst'.  'size' should hold the number
   of bytes allocated by the caller for the buffer 'dst'. */
void xlat_system_call(char * dst, int size, prstat_t p);

#endif
