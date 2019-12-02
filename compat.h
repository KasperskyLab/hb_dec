/*
 * Copyright (C) 2019  AO Kaspersky Lab
 * This program is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, write to the Free Software Foundation, 
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */ 


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
