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
 * $Id: //depot/argus/clients/include/argus_namedb.h#12 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifndef Argus_namedb_h
#define Argus_namedb_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 * As returned by the argus_next_etherent()
 * XXX this stuff doesn't belong in this inteface, but this
 * library already must do name to address translation, so
 * on systems that don't have support for /etc/ethers, we
 * export these hooks since they'll
 */

struct argus_etherent {
   unsigned char addr[6];
   char name[122];
};

#ifndef PCAP_ETHERS_FILE
#define PCAP_ETHERS_FILE "/etc/ethers"
#endif
struct argus_etherent *argus_next_etherent(FILE *);
unsigned char *argus_ether_hostton(char*);
unsigned char *argus_ether_aton(char *);

unsigned int **argus_nametoaddr(char *);
unsigned int argus_nametonetaddr(char *);

int argus_nametoport(char *, int *, int *);
int argus_nametoproto(char *);
int argus_nametoeproto(char *);

#define PROTO_UNDEF      -1

unsigned int   __argus_atodn(char *);
unsigned int   __argus_atoin(char *, unsigned int *);
unsigned short __argus_nametodnaddr(char *);

#ifdef __cplusplus
}
#endif
#endif
