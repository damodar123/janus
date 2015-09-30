/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <string.h>
#include <assert.h>

/*
 * match -- returns 1 if `string' satisfised `regex' and 0 otherwise
 * adapted from Spencer Sun: only recognizes * and \ as special characters
 * note non-shell-regexp-like behaviour:
 *   * will happily match /'s
 *   * will happily match .profile
 */
int	match(const char *regex, const char *string)
{
  const char *rp = regex, *sp = string, *save;
  char ch;

  assert(regex && string);
  while (*rp != '\0')
  {
    switch(ch = *rp++)
    {
      case '*':
        if ('\0' == *sp)  /* match empty string at end of `string' */
	  return ('\0' == *rp);  /* but only if we're done with the pattern */
	/* greedy algorithm: save starting location, then find end of string */
	save = sp;
	sp += strlen(sp);
	do
	{
	  if (match(rp, sp))  /* return success if we can match here */
	    return 1;
	} while (--sp >= save);  /* otherwise back up and try again */
	/*
	 * Backed up all the way to starting location (i.e. `*' matches
	 * empty string) and we _still_ can't match here.  Give up.
	 */
	return 0;
	/* break; not reached */
      case '\\':
	if ((ch = *rp++) == '\0')
	{
	  /* ill-formed pattern; backslash must be followed by a character */
	  return 0;
	}
	/* if not end of pattern, FALL THROUGH to match next char explicitly */
      default:	/* normal character */
	if (ch != *sp++)
	  return 0;
	break;
    }
  }
  /*
   * OK, we successfully matched the pattern if we got here.  Now return
   * a match if we also reached end of string, otherwise failure
   */
  return ('\0' == *sp);
}
