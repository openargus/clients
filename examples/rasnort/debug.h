/* $Id: debug.h,v 1.2 2004/05/14 15:44:35 qosient Exp $ */
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


#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG_VARIABLE "SNORT_DEBUG"

#define DEBUG_ALL             0xffffffff
#define DEBUG_INIT            0x00000001  /* 1 */
#define DEBUG_CONFIGRULES     0x00000002  /* 2 */
#define DEBUG_PLUGIN          0x00000004  /* 4 */
#define DEBUG_DATALINK        0x00000008  /* 8 */
#define DEBUG_IP              0x00000010  /* 16 */
#define DEBUG_TCPUDP          0x00000020  /* 32 */
#define DEBUG_DECODE          0x00000040  /* 64 */
#define DEBUG_LOG             0x00000080  /* 128 */
#define DEBUG_MSTRING         0x00000100  /* 256 */
#define DEBUG_PARSER          0x00000200  /* 512 */
#define DEBUG_PLUGBASE        0x00000400  /* 1024 */
#define DEBUG_RULES           0x00000800  /* 2048 */
#define DEBUG_FLOW            0x00001000  /* 4096 */
#define DEBUG_STREAM          0x00002000  /* 8192 */
#define DEBUG_PATTERN_MATCH   0x00004000  /* 16384 */
#define DEBUG_DETECT          0x00008000  /* 32768 */
#define DEBUG_CONVERSATION    0x00010000  /* 65536 */
#define DEBUG_FRAG2           0x00020000  /* 131072 */
#define DEBUG_HTTP_DECODE     0x00040000  /* 262144 */
#define DEBUG_PORTSCAN2       0x00080000  /* 524288 / (+ conv2 ) 589824 */
#define DEBUG_RPC             0x00100000  /* 1048576 */
#define DEBUG_FLOWSYS         0x00200000  /* 2097152 */
#define DEBUG_HTTPINSPECT     0x00400000  /* 4194304 */

#ifdef DEBUG

    extern char *DebugMessageFile;
    extern int DebugMessageLine;

    #define    DebugMessage    DebugMessageFile = __FILE__; DebugMessageLine = __LINE__; DebugMessageFunc

    void DebugMessageFunc(int , char *, ...);

    int GetDebugLevel (void);
    int DebugThis(int level);
#else 

#ifdef WIN32
/* Visual C++ uses the keyword "__inline" rather than "__inline__" */
         #define __inline__ __inline
#endif

#endif /* DEBUG */

#define DEBUG 1

#ifdef DEBUG
#define DEBUG_WRAP(code) code
void DebugMessageFunc(int dbg,char *fmt, ...);
#else
#define DEBUG_WRAP(code)
/* I would use DebugMessage(dbt,fmt...) but that only works with GCC */

#endif

#endif /* DEBUG_H */
