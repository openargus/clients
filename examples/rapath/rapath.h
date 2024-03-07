/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 * rapath.h  - Include file for rapath processing.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/rapath/rapath.h#4 $
 * $DateTime: 2014/10/07 15:23:30 $
 * $Change: 2939 $
 */


#ifndef RaPath_h
#define RaPath_h

#include <stdlib.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>


#include <netinet/in.h>
#include <ctype.h>

#include <argus_namedb.h>
#include <argus_filter.h>
 
#define RA_CON			1
#define RA_DONE			2

struct ArgusPathRecord {
   struct ArgusQueueHeader qhdr;
   struct RaHashTableHeader *rahtblhdr;
   struct ArgusRecord *argus;
};

#endif

