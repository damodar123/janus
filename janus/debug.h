/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */


#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern int debug;
extern int verbose;

#define ASSERT(x) assert(x)

/* debug messages -- only reported if debug flag set */
#define PDEBUG(fmt, ARGS...) do { if (debug) { fprintf(stderr, "DEBUG>> %s : %d:  " fmt "\n" , ## __FILE__ , ## __LINE__ , ## ARGS); } } while(0)

/* informative messages /always printed */
#define PINFO(fmt, ARGS...) fprintf(stdout,">> " fmt "\n" , ## ARGS)

/* verbose messages -- only reported if verbose flag set */
#define PVERBOSE(fmt, ARGS...) do { if (verbose) { fprintf(stderr,fmt, ## ARGS); } } while(0)

/* error messages -- always reported  */
#ifdef NOT_RELEASE
    #define PERROR(fmt, ARGS...) fprintf(stderr, "ERROR>> %s : %d:  " fmt "\n" , ## __FILE__ , ## __LINE__ , ## ARGS)
#else
    #define PERROR(fmt, ARGS...) fprintf(stderr, fmt "\n" ,  ## ARGS)
#endif

#endif

