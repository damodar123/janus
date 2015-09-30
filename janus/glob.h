/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */


#ifndef GLOB_H
#define GLOB_H

#include <string.h>

/*
 * match -- returns 1 if `string' satisfised `regex' and 0 otherwise
 * adapted from Spencer Sun: only recognizes * and \ as special characters
 * note non-shell-regexp-like behaviour:
 *   * will happily match /'s
 *   * will happily match .profile
 */

int	match(const char *regex, const char *string);

#endif
