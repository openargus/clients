/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_namedb.h#4 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
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
