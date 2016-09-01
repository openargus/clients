/* $Id: sp_respond.c,v 1.27 2003/12/17 21:25:14 jh8 Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 1999,2000,2001 Christian Lademann <cal@zls.de>
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

/* $Id: sp_respond.c,v 1.27 2003/12/17 21:25:14 jh8 Exp $ */

/*
 * CREDITS:
 *
 * The functionality presented here was inspired by
 * the program "couic" by Michel Arboi <arboi@bigfoot.com>
 *
*/

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif


#ifdef ENABLE_RESPONSE
#include <libnet.h>

#include "decode.h"
#include "rules.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "log.h"
#include "plugin_enum.h"
#include "snort.h"

typedef struct _RespondData
{
    u_int response_flag;
} RespondData;

void RespondInit(char *, OptTreeNode *, int ); 
void RespondRestartFunction(int, void *);
int ParseResponse(char *);
int SendICMP_UNREACH(int, u_long, u_long, Packet *);
int SendTCPRST(u_long, u_long, u_short, u_short, u_long, u_long);
int Respond(Packet *, RspFpList *);




int nd; /* raw socket descriptor */
u_int8_t ttl;   /* placeholder for randomly generated TTL */

char *tcp_pkt;
char *icmp_pkt;

void PrecacheTcp(void);
void PrecacheIcmp(void);

/**************************************************************************
 *
 * Function: SetupRespond();
 *
 * Purpose: Initialize repsond plugin
 *
 * Arguments: None.
 *
 * Returns: void
 **************************************************************************/

void SetupRespond(void)
{
    RegisterPlugin("resp", RespondInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: Respond Setup\n"););
    nd = -1;
}

void RespondRestartFunction(int signal, void *foo)
{
    if (nd != -1)
    {
        libnet_close_raw_sock(nd);
        nd = -1;
    }
    if (tcp_pkt != NULL)
        libnet_destroy_packet((u_char **)&tcp_pkt);
    if (icmp_pkt != NULL)
        libnet_destroy_packet((u_char **)&icmp_pkt);

    return;
}

void RespondInit(char *data, OptTreeNode *otn, int protocol) 
{
    RespondData *rd;

    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
       protocol != IPPROTO_ICMP)
    {
        FatalError("%s(%d): Can't respond to IP protocol rules\n", 
                   file_name, file_line);
    }
    if(nd == -1) /* need to open it only once */
    {
        if((nd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            FatalError("cannot open raw socket for libnet, exiting...\n");
        }
    }

    ttl = (u_int8_t)libnet_get_prand(PR8);

    if(ttl < 64)
    {
        ttl += 64;
    } 

    if(( rd = (RespondData *)calloc(sizeof(RespondData), sizeof(char))) == NULL)
    {
        FatalError("sp_respnd RespondInit() calloc failed!\n");
    }
    
    rd->response_flag = ParseResponse(data);
    
    AddRspFuncToList(Respond, otn, (void *)rd );
    AddFuncToRestartList(RespondRestartFunction, NULL);

    return;
}

/****************************************************************************
 *
 * Function: ParseResponse(char *)
 *
 * Purpose: Figure out how to handle hostile connection attempts
 *
 * Arguments: type => string of comma-sepatared modifiers
 *
 * Returns: void function
 *
 ***************************************************************************/
int ParseResponse(char *type)
{
    char *p;
    int response_flag;
    int make_tcp = 0;
    int make_icmp = 0;

    while(isspace((int) *type))
        type++;

    if(!type || !(*type))
        return 0;

    response_flag = 0;

    p = strtok(type, ",");
    while(p)
    {
        if(!strncasecmp(p, "rst_snd", 7))
        {
            response_flag |= RESP_RST_SND;
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "rst_rcv", 7))
        {
            response_flag |= RESP_RST_RCV;
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "rst_all", 7))
        {
            response_flag |= (RESP_RST_SND | RESP_RST_RCV);
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "icmp_net", 8))
        {
            response_flag |= RESP_BAD_NET;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_host", 9))
        {
            response_flag |= RESP_BAD_HOST;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_port", 9))
        {
            response_flag |= RESP_BAD_PORT;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_all", 9))
        {
            response_flag |= (RESP_BAD_NET | RESP_BAD_HOST | RESP_BAD_PORT);
            make_icmp = 1;
        }
        else
        {
            FatalError("%s(%d): invalid response modifier: %s\n", file_name, 
                    file_line, p);
        }

        p = strtok(NULL, ",");
    }

    if(make_tcp)
    {
        PrecacheTcp();
    }

    if(make_icmp)
    {
        /* someday came sooner than expected. -Jeff */
        PrecacheIcmp();
    }

    return response_flag;
}


void PrecacheTcp(void)
{
    int sz = IP_H + TCP_H;

    if((tcp_pkt = calloc(sz, sizeof(char))) == NULL)
    {
        FatalError("PrecacheTCP() calloc failed!\n");
    }

    libnet_build_ip(TCP_H, 0,
                    libnet_get_prand(PRu16) /* IP ID */ ,
                    0 /* fragmentation */ , ttl /* TTL */ , IPPROTO_TCP,
                    0, 0, NULL, 0, tcp_pkt);

    libnet_build_tcp(0, 0, 0, 0,
                     TH_RST|TH_ACK, 0, 0, NULL, 0, tcp_pkt + IP_H);

    return;
}

void PrecacheIcmp(void)
{
    int sz = IP_H + ICMP_UNREACH_H + 68;    /* plan for IP options */

    if((icmp_pkt = calloc(sz, sizeof(char))) == NULL)
    {
        FatalError("PrecacheIcmp() calloc failed!\n");
    }

    libnet_build_ip(ICMP_UNREACH_H, 0,
                    libnet_get_prand(PRu16) /* IP ID */ ,
                    0 /* fragmentation */ , ttl /* TTL */ , IPPROTO_ICMP,
                    0, 0, NULL, 0, icmp_pkt);

    libnet_build_icmp_unreach(3, 0, 0, 0, 0, 0, 0, 0,
                              0, 0, NULL, 0, icmp_pkt + IP_H);

    return;
}


/****************************************************************************

 *
 * Function: Respond(Packet *p, RspFpList)
 *
 * Purpose: Respond to hostile connection attempts
 *
 * Arguments:
 *
 * Returns: void function
 *
 ***************************************************************************/

int Respond(Packet *p, RspFpList *fp_list)
{
    RespondData *rd = (RespondData *)fp_list->params;

    if(!p->iph)
    {
        return 0;
    }
    
    if(rd->response_flag)
    {
        if(rd->response_flag & (RESP_RST_SND | RESP_RST_RCV))
        {
            if(p->iph->ip_proto == IPPROTO_TCP && p->tcph != NULL)
            {
                /*
                **  This ensures that we don't reset packets that we just
                **  spoofed ourselves, thus inflicting a self-induced DOS
                **  attack.
                **
                **  We still reset packets that may have the SYN set, though.
                */
                if((p->tcph->th_flags & (TH_SYN | TH_RST)) != TH_RST)
                {
                    if(rd->response_flag & RESP_RST_SND)
                    {
                        SendTCPRST(p->iph->ip_dst.s_addr, 
                                   p->iph->ip_src.s_addr,
                                   p->tcph->th_dport, p->tcph->th_sport,
                                   p->tcph->th_ack, 
                                   htonl(ntohl(p->tcph->th_seq) + p->dsize));
                    }

                    if(rd->response_flag & RESP_RST_RCV)
                    {
                        SendTCPRST(p->iph->ip_src.s_addr, 
                                   p->iph->ip_dst.s_addr,
                                   p->tcph->th_sport, p->tcph->th_dport, 
                                   p->tcph->th_seq, 
                                   htonl(ntohl(p->tcph->th_ack) + p->dsize));
                    }
                }
            }
        }

        /*
        **  We check that we only reset packets with an ICMP packet if it is
        **  valid.  This means that we don't reset ICMP error types and will
        **  only reset ICMP query request.
        */
        if((p->icmph == NULL) || 
           (p->icmph->type == ICMP_ECHO) ||
           (p->icmph->type == ICMP_TIMESTAMP) || 
           (p->icmph->type == ICMP_INFO_REQUEST) ||
           (p->icmph->type == ICMP_ADDRESS))
        {
            if(rd->response_flag & RESP_BAD_NET)
                SendICMP_UNREACH(ICMP_UNREACH_NET, p->iph->ip_dst.s_addr,
                                 p->iph->ip_src.s_addr, p);

            if(rd->response_flag & RESP_BAD_HOST)
                SendICMP_UNREACH(ICMP_UNREACH_HOST, p->iph->ip_dst.s_addr,
                                 p->iph->ip_src.s_addr, p);

            if(rd->response_flag & RESP_BAD_PORT)
                SendICMP_UNREACH(ICMP_UNREACH_PORT, p->iph->ip_dst.s_addr,
                                 p->iph->ip_src.s_addr, p);
        }
    }
    return 1; /* always success */
}


int SendICMP_UNREACH(int code, u_long saddr, u_long daddr, Packet * p)
{
    int payload_len, sz;
    IPHdr *iph;
    ICMPHdr *icmph;

    if(p == NULL)
        return -1;

    /* don't send ICMP port unreachable errors in response to ICMP messages */
    if (p->iph->ip_proto == 1 && code == ICMP_UNREACH_PORT)
    {
        if (pv.verbose_flag)
        {
            ErrorMessage("ignoring icmp_port set on ICMP packet.\n");
        }
        
        return 0;
    }

    iph = (IPHdr *) icmp_pkt;
    icmph = (ICMPHdr *) (icmp_pkt + IP_H);

    iph->ip_src.s_addr = saddr;
    iph->ip_dst.s_addr = daddr;

    icmph->code = code;

    if ((payload_len = ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)) > 8)
        payload_len = 8;

    memcpy((char *)icmph + ICMP_UNREACH_H, p->iph, (IP_HLEN(p->iph) << 2)
            + payload_len);

    sz = IP_H + ICMP_UNREACH_H + (IP_HLEN(p->iph) << 2) + payload_len;
    iph->ip_len = htons(sz);

    libnet_do_checksum(icmp_pkt, IPPROTO_ICMP, sz - IP_H);

#ifdef DEBUG
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "firing ICMP response packet\n"););
    PrintNetData(stdout, icmp_pkt, sz);
    ClearDumpBuf();
#endif
    if(libnet_write_ip(nd, icmp_pkt, sz) < sz)
    {
        libnet_error(LIBNET_ERR_CRITICAL, "SendICMP_UNREACH: libnet_write_ip");
        return -1;
    }
    return 0;
}


int SendTCPRST(u_long saddr, u_long daddr, u_short sport, u_short dport, 
        u_long seq, u_long ack)
{
    int sz = IP_H + TCP_H;
    IPHdr *iph;
    TCPHdr *tcph;

    iph = (IPHdr *) tcp_pkt;
    tcph = (TCPHdr *) (tcp_pkt + IP_H);

    iph->ip_src.s_addr = saddr;
    iph->ip_dst.s_addr = daddr;

    tcph->th_sport = sport;
    tcph->th_dport = dport;
    tcph->th_seq = seq;
    tcph->th_ack = ack;

    libnet_do_checksum(tcp_pkt, IPPROTO_TCP, sz - IP_H);
    
    DEBUG_WRAP(
	       PrintNetData(stdout, tcp_pkt, sz);
	       ClearDumpBuf();
	       DebugMessage(DEBUG_PLUGIN, "firing response packet\n");
	       DebugMessage(DEBUG_PLUGIN,
                   "0x%lX:%u -> 0x%lX:%d (seq: 0x%lX  ack: 0x%lX)\n",
			        saddr, sport, daddr, dport, seq, ack););
    
    if(libnet_write_ip(nd, tcp_pkt, sz) < sz)
    {
        libnet_error(LIBNET_ERR_CRITICAL, "SendTCPRST: libnet_write_ip");
        return -1;
    }

    return 0;
}

#endif
