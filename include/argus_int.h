/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* 
 * $Id: //depot/argus/clients/include/argus_int.h#14 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifndef Argus_int_h
#define Argus_int_h

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__STDC__)
#define const
#endif

#if !defined(__GNUC__)
#define inline
#endif

#include <argus_os.h>		/* os dependent stuff */

#ifndef SIGRET
#define SIGRET void             /* default */
#endif

struct ArgusTokenStruct {
   int v;                  /* value */
   char *s;                /* string */
};
 
struct ArgusInterfaceStruct {
   int value; 
   char *label; 
   char *desc; 
}; 

#define MIN_SNAPLEN 96

#if defined(ArgusUtil)
    
struct ArgusInterfaceStruct ArgusInterfaceTypes [] = {
{  0, "DLT_NULL", "no link-layer encapsulation"},
{  1, "DLT_EN10MB", "Ethernet (10Mb)"},
{  2, "DLT_EN3MB", "Experimental Ethernet (3Mb)"},
{  3, "DLT_AX25", "Amateur Radio AX.25"},
{  4, "DLT_PRONET", "Proteon ProNET Token Ring"},
{  5, "DLT_CHAOS", "Chaos"},
{  6, "DLT_IEEE802", "IEEE 802 Networks"},
{  7, "DLT_ARCNET", "ARCNET"},
{  8, "DLT_SLIP", "Serial Line IP"},
{  9, "DLT_PPP",  "Point-to-point Protocol"},
{ 10,"DLT_FDDI", "FDDI"},
{ 11, "DLT_ATM_RFC1483", "LLC/SNAP encapsulated atm"},
{ 12, "DLT_LOOP", "loopback"},
{ 13, "DLT_SLIP_BSDOS", "BSD/OS Serial Line IP"},
{ 14, "DLT_PPP_BSDOS", "BSD/OS Point-to-point"},
{ 15, "DLT_SLIP_BSDOS", "BSD/OS Serial Line IP"},
{ 16, "DLT_PPP_BSDOS", "BSD/OS Point-to-point"},
{ 19, "DLT_ATM_CLIP", "Linux Classical-IP over ATM"},
{ 50, "DLT_PPP_SERIAL", "PPP over Serial with HDLC"},
{ 51, "DLT_PPP_ETHER", "PPP over Ethernet"},

{100, "DLT_ATM_RFC1483", "LLC/SNAP encapsulated atm"},
{101, "DLT_RAW", "raw IP"},
{102, "DLT_SLIP_BSDOS", "BSD/OS Serial Line IP"},
{103, "DLT_PPP_BSDOS", "BSD/OS Point-to-point Protocol"},
{104, "DLT_CHDLC", "Cisco HDLC"},
{105, "DLT_IEEE802_11", "IEE 802.11 wireless"},
{-1, "Undefined", "Undefined"},
};

#else
extern struct ArgusInterfaceStruct ArgusInterfaceTypes[];
#endif

#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#define max(a,b) ((b)>(a)?(b):(a))
#endif

extern char timestamp_fmt[];
extern long timestamp_scale;
extern void timestampinit(void);

extern int fn_print(const u_char *, const u_char *, char *);
extern int fn_printn(const u_char *, u_int, const u_char *, char *);
extern char *dnaddr_string(u_short);
extern char *savestr(const char *);

extern char *isonsap_string(const u_char *, int);
extern char *llcsap_string(u_char);
extern char *protoid_string(const u_char *);
extern char *dnname_string(u_short);
extern char *dnnum_string(u_short);

#ifdef __cplusplus
}
#endif
#endif /* Argus_int_h */

