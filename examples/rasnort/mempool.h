/* $Id: mempool.h,v 1.1 2004/05/12 00:04:26 qosient Exp $ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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


#ifndef _MEMPOOL_H
#define _MEMPOOL_H

#include "sf_sdlist.h"

typedef unsigned int PoolCount;

typedef struct _MemBucket
{
    SDListItem *key;
    int used;
    void *data;
} MemBucket;

typedef struct _MemPool
{
    void **datapool; /* memory buffer for MemBucket->data */
    
    MemBucket *bucketpool; /* memory buffer */

    SDListItem *listpool; /* list of things to use for memory bufs */

    PoolCount free; /*  free block count */
    PoolCount used;  /* used block count */

    PoolCount total;
    
    sfSDList free_list;
    sfSDList used_list;
    
    size_t obj_size;    
} MemPool;

int mempool_init(MemPool *mempool, PoolCount num_objects, size_t obj_size);
int mempool_destroy(MemPool *mempool);
MemBucket *mempool_alloc(MemPool *mempool);
void mempool_free(MemPool *mempool, MemBucket *obj);

#endif /* _MEMPOOL_H */


