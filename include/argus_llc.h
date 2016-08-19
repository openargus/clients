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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_llc.h#6 $
 * $DateTime: 2006/02/23 13:25:52 $
 * $Change: 627 $
 */

#ifndef Argus_llc_h
#define Argus_llc_h

#ifdef __cplusplus
extern "C" {
#endif

struct llc {
   u_char dsap;
   u_char ssap;
   union {
      u_char u_ctl;
      u_short is_ctl;
      struct {
         u_char snap_ui;
         u_char snap_pi[5];
      } snap;
      struct {
         u_char snap_ui;
         u_char snap_orgcode[3];
         u_char snap_ethertype[2];
      } snap_ether;
   } ctl;
};

#define llcui              ctl.snap.snap_ui
#define llcpi              ctl.snap.snap_pi
#define orgcode            ctl.snap_ether.snap_orgcode
#define snapetype          ctl.snap_ether.snap_ethertype
#define llcis              ctl.is_ctl
#define llcu               ctl.u_ctl

#define LLC_U_FMT          3
#define LLC_GSAP           1
#define LLC_IG             1 
#define LLC_S_FMT          1

#define LLC_U_POLL         0x10
#define LLC_IS_POLL        0x0001
#define LLC_XID_FI         0x81

#define LLC_U_CMD(u)       ((u) & 0xef)
#define LLC_UI             0x03
#define LLC_UA             0x63
#define LLC_DISC           0x43
#define LLC_DM             0x0f
#define LLC_SABME          0x6f
#define LLC_TEST           0xe3
#define LLC_XID            0xaf
#define LLC_FRMR           0x87

#define LLC_S_CMD(is)      (((is) >> 10) & 0x03)
#define LLC_RR             0x0100
#define LLC_RNR            0x0500
#define LLC_REJ            0x0900

#define LLC_IS_NR(is)      (((is) >> 1) & 0x7f)
#define LLC_I_NS(is)       (((is) >> 9) & 0x7f)

#ifndef LLCSAP_NULL
#define LLCSAP_NULL        0x00
#endif
#ifndef LLCSAP_8021B_I
#define LLCSAP_8021B_I     0x02
#endif
#ifndef LLCSAP_8021B_G
#define LLCSAP_8021B_G     0x03
#endif
#ifndef LLCSAP_SNAPATH
#define LLCSAP_SNAPATH     0x04
#endif
#ifndef LLCSAP_IP
#define LLCSAP_IP          0x06
#endif
#ifndef LLCSAP_SNA1
#define LLCSAP_SNA1        0x08
#endif
#ifndef LLCSAP_SNA2
#define LLCSAP_SNA2        0x0c
#endif
#ifndef LLCSAP_PROWAYNM
#define LLCSAP_PROWAYNM    0x0e
#endif
#ifndef LLCSAP_TI
#define LLCSAP_TI          0x18
#endif
#ifndef LLCSAP_BPDU
#define LLCSAP_BPDU        0x42
#endif
#ifndef LLCSAP_RS511
#define LLCSAP_RS511       0x4e
#endif
#ifndef LLCSAP_ISO8208
#define LLCSAP_ISO8208     0x7e
#endif
#ifndef LLCSAP_XNS
#define LLCSAP_XNS         0x80
#endif
#ifndef LLCSAP_NESTAR
#define LLCSAP_NESTAR      0x86
#endif
#ifndef LLCSAP_PROWAYASLM
#define LLCSAP_PROWAYASLM  0x8e
#endif
#ifndef LLCSAP_ARP
#define LLCSAP_ARP         0x98
#endif
#ifndef LLCSAP_SNAP
#define LLCSAP_SNAP        0xaa
#endif
#ifndef LLCSAP_VINES1
#define LLCSAP_VINES1      0xba
#endif
#ifndef LLCSAP_VINES2
#define LLCSAP_VINES2      0xbc
#endif
#ifndef LLCSAP_NETWARE
#define LLCSAP_NETWARE     0xe0
#endif
#ifndef LLCSAP_NETBIOS
#define LLCSAP_NETBIOS     0xf0
#endif
#ifndef LLCSAP_IBMNM
#define LLCSAP_IBMNM       0xf4
#endif
#ifndef LLCSAP_RPL1
#define LLCSAP_RPL1        0xf8
#endif
#ifndef LLCSAP_UB
#define LLCSAP_UB          0xfa
#endif
#ifndef LLCSAP_RPL2
#define LLCSAP_RPL2        0xfc
#endif
#ifndef LLCSAP_ISONS
#define LLCSAP_ISONS       0xfe
#endif
#ifndef LLCSAP_GLOBAL
#define LLCSAP_GLOBAL      0xff
#endif

#ifdef __cplusplus
}
#endif
#endif
