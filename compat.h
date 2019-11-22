#ifndef compat_h_included
#define compat_h_included

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#ifdef __WIN32
#define memmem gitmemmem
void *gitmemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
#endif

#ifndef __WIN32
#define O_BINARY 0
#endif

#ifdef __cplusplus
}
#endif

#endif
