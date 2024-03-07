/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id: sp_pattern_match.h,v 1.19 2003/10/20 15:03:31 chrisgreen Exp $ */

#ifndef __SP_PATTERN_MATCH_H__
#define __SP_PATTERN_MATCH_H__

#include "snort.h"
#include "debug.h"
#include "rules.h" /* needed for OptTreeNode defintion */
#include <ctype.h>

typedef struct _PatternMatchData
{
    u_int8_t exception_flag; /* search for "not this pattern" */
    int offset;             /* pattern search start offset */
    int depth;              /* pattern search depth */

    int distance;           /* offset to start from based on last match */
    int within;             /* this pattern must be found 
                               within X bytes of last match*/
    int rawbytes;           /* Search the raw bytes rather than any decoded app
                               buffer */

    int nocase;             /* Toggle case insensitity */
    int use_doe;            /* Use the doe_ptr for relative pattern searching */
    u_int pattern_size;     /* size of app layer pattern */
    char *pattern_buf;      /* app layer pattern to match on */
    int (*search)(char *, int, struct _PatternMatchData *);  /* search function */
    int *skip_stride; /* B-M skip array */
    int *shift_stride; /* B-M shift array */
    struct _PatternMatchData *next; /* ptr to next match struct */
} PatternMatchData;

void SetupPatternMatch(void);
int SetUseDoePtr(OptTreeNode *otn);

#endif /* __SP_PATTERN_MATCH_H__ */
