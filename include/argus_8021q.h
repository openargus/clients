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
