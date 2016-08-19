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
 * $Id: //depot/argus/argus-3.0/clients/include/netinet/rtp.h#5 $
 * $DateTime: 2006/02/02 18:35:52 $
 * $Change: 574 $
 */


#ifndef _netinet_rtp_h
#define _netinet_rtp_h

/* RTP Upper Layer Format Numbers H.225 */


#define	IPPROTO_RTP	257

#define RTP_PCMU	0
#define RTP_PCMA	8
#define RTP_G722	9
#define RTP_G723	4
#define RTP_G728	15
#define RTP_G729	18
#define RTP_H261	31
#define RTP_H263	34

/* RTP Header as defined in H.225 */

struct rtphdr {
#ifdef _LITTLE_ENDIAN
  unsigned char rh_cc:4,    /* CSRC count */
                 rh_x:1,    /* extension */
                 rh_p:1,    /* padding */
                rh_ver:2;   /* version */
#else
  unsigned char rh_ver:2,    /* version */
                  rh_p:1,    /* padding */
                  rh_x:1,    /* extension */
                 rh_cc:4;   /* CSRC count */
#endif
#ifdef _LITTLE_ENDIAN
  unsigned char   rh_pt:7,   /* payload type */
                rh_mark:1;   /* marker */
#else
  unsigned char rh_mark:1,   /* marker */
                  rh_pt:7;   /* payload type */
#endif
   unsigned short rh_seq;
   unsigned int   rh_time;
   unsigned int   rh_ssrc;
};


struct rtcphdr {
#ifdef _LITTLE_ENDIAN
  unsigned char  rh_rc:5,    /* report count */
                  rh_p:1,    /* padding */
                rh_ver:2;    /* version */
#else
  unsigned char rh_ver:2,    /* version */
                  rh_p:1,    /* padding */
                 rh_rc:5;    /* report count */
#endif
   unsigned char  rh_pt;     /* payload type */
   unsigned short rh_len;
   unsigned int   rh_ssrc;
};


struct rtpexthdr {
   unsigned short profile, length;
};
#endif /*!_netinet_rtp_h*/
