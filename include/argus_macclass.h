/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_macclass.h#5 $
 * $DateTime: 2015/04/13 16:50:31 $
 * $Change: 2993 $
 */


/* list of supported encapsulations for filter */


#ifndef  Argus_MacClass_h
#define Argus_MacClass_h

#ifdef __cplusplus
extern "C" {
#endif

struct ArgusMacClassStruct {
   unsigned int id;
   char *class, *desc;
   unsigned char mask, value;
};

#define ARGUS_ETHER_CLASSMASK   0x0F

#define ARGUS_ETHER_UNICAST     0x0100
#define ARGUS_ETHER_MULTICAST   0x0001
#define ARGUS_ETHER_UAA         0x0002
#define ARGUS_ETHER_LAA         0x0004
#define ARGUS_ETHER_LM          (ARGUS_ETHER_LAA | ARGUS_ETHER_MULTICAST)
#define ARGUS_ETHER_SLAP_ELI    0x0010
#define ARGUS_ETHER_SLAP_SAI    0x0020
#define ARGUS_ETHER_SLAP_AAI    0x0040
#define ARGUS_ETHER_SLAP_RES    0x0080

#if defined(ArgusUtil)
struct ArgusMacClassStruct argus_macclass [] = {
   { ARGUS_ETHER_UNICAST,   "uni", "Unicast Address", 0x01, 0x00},
   { ARGUS_ETHER_MULTICAST, "multi", "Multicast Address", 0x01, 0x01},
   { ARGUS_ETHER_UAA,       "uaa", "Universally Administered Address", 0x02, 0x00},
   { ARGUS_ETHER_LAA,       "laa", "Locally Administered Address", 0x02, 0x01},
   { ARGUS_ETHER_LM,        "lm", "Local Mulitcast Address", 0x07, 0x03},
   { ARGUS_ETHER_SLAP_ELI,  "eli", "Extended Local IEEE", 0x0F, 0x0A},
   { ARGUS_ETHER_SLAP_SAI,  "sai", "Standard Assigned BARC", 0x0F, 0x0E},
   { ARGUS_ETHER_SLAP_AAI,  "aai", "Administratively Assigned", 0x0F, 0x02},
   { ARGUS_ETHER_SLAP_RES,  "res", "Reserved", 0x0F, 0x06},
   { 0, (char *) NULL, (char *) NULL, 0, 0 }, 
};

#else

extern struct ArgusMacClassStruct argus_macclass [];

#endif
#ifdef __cplusplus
}
#endif
#endif
