/*
 * Copyright (c) 1988-2002
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @(#) $Header: /tcpdump/master/tcpdump/interface.h,v 1.244.2.18 2005/09/29 07:46:45 hannes Exp $ (LBL)
 */

#ifndef tcpdump_interface_h
#define tcpdump_interface_h

#define PT_VAT		1	/* Visual Audio Tool */
#define PT_WB		2	/* distributed White Board */
#define PT_RPC		3	/* Remote Procedure Call */
#define PT_RTP		4	/* Real-Time Applications protocol */
#define PT_RTCP		5	/* Real-Time Applications control protocol */
#define PT_SNMP		6	/* Simple Network Management Protocol */
#define PT_CNFP		7	/* Cisco NetFlow protocol */
#define PT_TFTP		8	/* trivial file transfer protocol */
#define PT_AODV		9	/* Ad-hoc On-demand Distance Vector Protocol */

#ifndef TELNET_PORT
#define TELNET_PORT		23
#endif
#ifndef NAMESERVER_PORT
#define NAMESERVER_PORT		53
#endif
#ifndef BGP_PORT
#define BGP_PORT		179
#endif
#ifndef NETBIOS_SSN_PORT
#define NETBIOS_SSN_PORT	139
#endif
#ifndef MULTICASTDNS_PORT
#define MULTICASTDNS_PORT	5353
#endif
#ifndef PPTP_PORT
#define PPTP_PORT		1723
#endif
#ifndef BEEP_PORT
#define BEEP_PORT		10288
#endif
#ifndef NFS_PORT
#define NFS_PORT		2049
#endif
#define IPPORT_BOOTPS           67
#define IPPORT_BOOTPC           68
#define MSDP_PORT       639
#define LDP_PORT        646
#define TFTP_PORT 69      /*XXX*/
#define KERBEROS_PORT 88   /*XXX*/
#define SUNRPC_PORT 111      /*XXX*/
#define SNMP_PORT 161      /*XXX*/
#define NTP_PORT 123      /*XXX*/
#define SNMPTRAP_PORT 162   /*XXX*/
#define ISAKMP_PORT 500      /*XXX*/
#define SYSLOG_PORT 514         /* rfc3164 */
#define TIMED_PORT 525      /*XXX*/
#define RIP_PORT 520      /*XXX*/
#define LDP_PORT 646
#define AODV_PORT 654      /*XXX*/
#define KERBEROS_SEC_PORT 750   /*XXX*/
#define L2TP_PORT 1701      /*XXX*/
#define SIP_PORT 5060
#define ISAKMP_PORT_NATT  4500  /* rfc3948 */
#define ISAKMP_PORT_USER1 7500   /*XXX - nonstandard*/
#define ISAKMP_PORT_USER2 8500   /*XXX - nonstandard*/
#define RX_PORT_LOW 7000   /*XXX*/
#define RX_PORT_HIGH 7009   /*XXX*/
#define NETBIOS_NS_PORT   137
#define NETBIOS_DGRAM_PORT   138
#define CISCO_AUTORP_PORT 496   /*XXX*/
#define RADIUS_PORT 1645
#define RADIUS_NEW_PORT 1812
#define RADIUS_ACCOUNTING_PORT 1646
#define RADIUS_NEW_ACCOUNTING_PORT 1813
#define HSRP_PORT 1985      /*XXX*/
#define LWRES_PORT      921
#define ZEPHYR_SRV_PORT      2103
#define ZEPHYR_CLT_PORT      2104
#define MPLS_LSP_PING_PORT      3503 /* draft-ietf-mpls-lsp-ping-02.txt */
#define BFD_CONTROL_PORT        3784 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */
#define BFD_ECHO_PORT           3785 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */
#define LMP_PORT                49998 /* unofficial - no IANA assignment yet */
#define RIPNG_PORT 521      /*XXX*/
#define DHCP6_SERV_PORT 546   /*XXX*/
#define DHCP6_CLI_PORT 547   /*XXX*/
 
/*
 * True if  "l" bytes of "var" were captured.
 *
 * The "snapend - (l) <= snapend" checks to make sure "l" isn't so large
 * that "snapend - (l)" underflows.
 *
 * The check is for <= rather than < because "l" might be 0.
 */
#define TTEST2(var, l) (snapend - (l) <= snapend && \
			(const u_char *)&(var) <= snapend - (l))

/* True if "var" was captured */
#define TTEST(var) TTEST2(var, sizeof(var))

/* Bail if "l" bytes of "var" were not captured */
#define TCHECK2(var, l) if (!TTEST2(var, l)) goto trunc

/* Bail if "var" was not captured */
#define TCHECK(var) TCHECK2(var, sizeof(var))

void safeputchar(int);

extern const char *tok2strbuf(const struct tok *, const char *, int, char *, size_t);
extern char *tok2str(const struct tok *, const char *, int);
extern char *bittok2str(const struct tok *, const char *, int);

extern int mask2plen (u_int32_t);
extern int decode_prefix4(const u_char *pptr, char *buf, u_int buflen);
extern int print_unknown_data(const u_char *, const char *, int);
extern void hex_print_with_offset(const char *, const u_char *, u_int, u_int);

extern char * aodv_print(const u_char *, u_int, int);
extern char * arp_src_print(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus);
extern char * arp_dst_print(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus);
extern char * bfd_print(const u_char *, u_int, u_int);
extern char * bgp_print(const u_char *, int);
extern char * beep_print(const u_char *, u_int);
extern char * bootp_print(const u_char *, u_int);
extern char * krb_print(const u_char *, u_int);
extern char * l2tp_print(const u_char *, u_int);
extern char * ldp_print(const u_char *, u_int);
extern char * lmp_print(const u_char *, u_int);
extern char * msdp_print(const u_char *, u_int);
extern char * ntp_print(const u_char *, u_int);
extern char * ns_print(const u_char *, u_int, int);
extern char * pim_print(const u_char *, u_int);
extern char * pptp_print(const u_char *, u_int);
extern char * rip_print(const u_char *, u_int);
extern char * snmp_print(const u_char *, u_int);
extern char * syslog_print(const u_char *, u_int);
extern char * stp_print(const u_char *, u_int);
extern char * telnet_print(const u_char *, u_int);
extern char * tftp_print(const u_char *, u_int);
extern char * timed_print(const u_char *, u_int);
extern char * radius_print(const u_int8_t *, u_int);
extern char * nbt_tcp_print(const u_char *, int);
extern char * nbt_udp137_print(const u_char *, int);
extern char * nbt_udp138_print(const u_char *, int);
extern char * isoclns_print(const u_int8_t *, u_int, u_int);
extern char * rx_print(const u_int8_t *, int, int, int);
extern char * isakmp_print(const u_char *, u_int);
extern char * isakmp_rfc3948_print(const u_char *, u_int);
extern char * dvmrp_print(const u_char *, u_int);
extern char * igmp_print(const u_char *, u_int);
extern char * pimv1_print(const u_char *, u_int);

extern void print_data(const unsigned char *, int);
extern const char *nt_errstr(u_int32_t);
extern char *smb_errstr(int, int);
extern void ipx_netbios_print(const u_char *, u_int);
extern void netbeui_print(u_short, const u_char *, int);

#endif
