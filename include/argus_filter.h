/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * Copyright (c) 1990, 1991, 1992, 1993
 *   The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence 
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *   This product includes software developed by the University of
 *   California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *   @(#)bpf.c   7.5 (Berkeley) 7/15/91
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_filter.h#7 $
 * $DateTime: 2014/10/07 14:26:13 $
 * $Change: 2933 $
 */


#ifndef ArgusFilter_h
#define ArgusFilter_h


#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include <net/nff.h>
#include <argus/gencode.h>

#ifndef __GNUC__
#define inline
#endif

/*
 * If a protocol is unknown, PROTO_UNDEF is returned.
 * Also, s_nametoport() returns the protocol along with the port number.
 * If there are ambiguous entried in /etc/services (i.e. domain
 * can be either tcp or udp) PROTO_UNDEF is returned.
 */
#define PROTO_UNDEF             -1



#ifdef ArgusFilter
#include <stdio.h>

void ArgusPrintHex (const unsigned char *, unsigned int);

int ArgusLookupNet(char *, unsigned int *, unsigned int *, char *);

char *read_infile(char *);

static inline int xdtoi(int c);
int ArgusFilterRecord (struct nff_insn *pc,  struct ArgusRecordStruct *);
int ArgusFilterOrig (struct nff_insn *, struct ArgusRecordStruct *, int, int);

static inline int skip_space(FILE *);
static inline int skip_line(FILE *);

static inline int skip_space(FILE *);
static inline int skip_line(FILE *);
struct argus_etherent *argus_next_etherent(FILE *fp);
char *ArgusLookupDev(char *);

char *argus_strerror(int);

void Argusnff_optimize(struct ablock **);

struct nff_insn *Argusicode_to_fcode(struct ablock *, int *);
static char *nff_image(struct nff_insn *, int);
int stoi( char *);

int ArgusCurses = 0;


#ifdef NOVFPRINTF
int vfprintf( FILE *, char *, va_list);
#endif

void ArgusDebug (int, char *, ...);
void *ArgusMalloc (int);
void *ArgusCalloc (int, int);
void ArgusFree (void *);

void ArgusWindowClose(void);

#if defined(__STDC__)
void error(const char *fmt, ...);
#else
void error(const char *fmt, va_dcl);
#endif

char *savestr(const char *);
char *copy_argv( char **);
char *read_infile(char *);
unsigned int ipaddrtonetmask(unsigned int);
unsigned int getnetnumber(unsigned int);

void nff_dump(struct nff_program *, int);

char *intoa(unsigned int);
extern SIGRET nohostname(int);
extern char *ArgusGetName(struct ArgusParserStruct *, unsigned char *);
extern char *ArgusGetV6Name(struct ArgusParserStruct *, unsigned char *);
extern struct enamemem *lookup_emem(struct enamemem *, const unsigned char *);

char *ArgusEtherProtoString(struct ArgusParserStruct *, unsigned short port);
char *linkaddr_string(struct ArgusParserStruct *parser, unsigned char *, unsigned int);
char *etheraddr_string(struct ArgusParserStruct *parser, unsigned char *);
int etheraddr_class(struct ArgusParserStruct *parser, unsigned char *);
char *etheraddr_oui(struct ArgusParserStruct *parser, unsigned char *);
char *protoid_string(const unsigned char *);
char *llcsap_string(unsigned char);
char *isonsap_string(const unsigned char *, int);
char *tcpport_string(unsigned short);
char *udpport_string(unsigned short);
char *icmpport_string(struct ArgusRecordStruct *, int);

extern void init_servarray(void);
extern void init_eprotoarray(void);
extern void init_protoidarray(void);
extern void init_etherarray(void);
extern void init_llcsaparray(void);

void init_addrtoname(int, unsigned int, unsigned int);
unsigned int **argus_nametoaddr(char *);
unsigned int argus_nametonetaddr(char *);
int argus_nametoport(char *, int *, int *);
int argus_nametoproto(char *);
int argus_nametoeproto(char *);
unsigned int __argus_atoin(char *, unsigned int *);
unsigned int __argus_atodn(char *);

unsigned char *argus_ether_aton(char *);
unsigned char *argus_ether_hostton(char *);
unsigned short __argus_nametodnaddr(char *);


#else

extern void ArgusPrintHex (const unsigned char *, unsigned int);
extern int ArgusLookupNet(char *, unsigned int *, unsigned int *, char *);
extern char *read_infile(char *);

extern int ArgusFilterRecord (struct nff_insn *pc,  struct ArgusRecordStruct *);
extern int ArgusFilterOrig (struct nff_insn *, u_char *, int, int);

extern struct argus_etherent *argus_next_etherent(FILE *fp);
extern char *ArgusLookupDev(char *);

extern char *argus_strerror(int);

extern void Argusnff_optimize(struct ablock **);

extern struct nff_insn *Argusicode_to_fcode(struct ablock *, int *);
extern int stoi( char *);

extern int ArgusCurses;

extern void ArgusWindowClose(void);

#ifdef NOVFPRINTF
extern int vfprintf( FILE *, char *, va_list);
#endif

extern void *ArgusMalloc (int);
extern void *ArgusCalloc (int, int);
extern void ArgusFree (void *);

/*
extern void error(va_list);
extern void warning(va_list);
*/

extern char *savestr(const char *);
extern char *copy_argv( char **);
extern char *read_infile(char *);
extern unsigned int ipaddrtonetmask(unsigned int);
extern unsigned int getnetnumber(unsigned int);

extern void nff_dump(struct nff_program *, int);

extern char *intoa(unsigned int);
extern char *ArgusGetName(struct ArgusParserStruct *, unsigned char *);
extern char *ArgusGetV6Name(struct ArgusParserStruct *, unsigned char *);

extern char *ArgusEtherProtoString(struct ArgusParserStruct *, unsigned short);
extern char *linkaddr_string(struct ArgusParserStruct *parser, const unsigned char *, unsigned int);
extern char *etheraddr_string(struct ArgusParserStruct *parser, unsigned char *);
extern int etheraddr_class(struct ArgusParserStruct *parser, unsigned char *);
extern char *etheraddr_oui(struct ArgusParserStruct *parser, unsigned char *);
extern char *protoid_string(const unsigned char *);
extern char *llcsap_string(unsigned char);
extern char *isonsap_string(const unsigned char *, int);
extern char *tcpport_string(unsigned short);
extern char *udpport_string(unsigned short);
extern char *icmpport_string(struct ArgusRecordStruct *, int);

extern void init_addrtoname(int, unsigned int, unsigned int);
extern unsigned int **argus_nametoaddr(char *);
extern unsigned int argus_nametonetaddr(char *);
extern int argus_nametoport(char *, int *, int *);
extern int argus_nametoproto(char *);
extern int argus_nametoeproto(char *);
extern unsigned int __argus_atoin(char *, unsigned int *);
extern unsigned int __argus_atodn(char *);

extern unsigned char *argus_ether_aton(char *);
extern unsigned char *argus_ether_hostton(char *);
extern unsigned short __argus_nametodnaddr(char *);

#endif
#ifdef __cplusplus
}
#endif

#endif  /* ArgusFilter_h */

