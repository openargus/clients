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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_8021q.h#5 $
 * $DateTime: 2006/03/31 13:25:33 $
 * $Change: 793 $
 */
/* 802.1q frame encaps */

#ifndef __ARGUS_8021Q__
#define __ARGUS_8021Q__

#ifdef __cplusplus
extern "C" {
#endif

struct ether_8021q { 
  struct      ether_header   ether;
  u_int16_t                  _8021q_prio   :  3;
  u_int16_t                  _8021q_canon  :  1;
  u_int16_t                  _8021q_vlanid : 12;
  u_int16_t                  len; 
} __attribute__ ((__packed__));

#define ETHER_8021Q_HDR_LEN   sizeof( struct ether_8021q )

#ifdef __cplusplus
}
#endif
#endif
