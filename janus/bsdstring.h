/* I think strlcat and strlcpy are keen, these implementations
are from the OpenBSD string library. */
#ifndef __BSDSTRING_H
#define __BSDSTRING_H

size_t strlcat( char *dst, const char *src, size_t siz);
size_t strlcpy( char *dst, const char *src, size_t siz);

#endif

