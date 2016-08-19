/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>

extern u_char *snapend;

#include "isakmp.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "interface.h"
#include "argus/extract.h"                    /* must come after interface.h */

extern char ArgusBuf[];

#ifndef HAVE_SOCKADDR_STORAGE
#define sockaddr_storage sockaddr
#endif

static const u_char *isakmp_sa_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_p_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_t_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_ke_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_id_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_cert_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_cr_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_sig_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_hash_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_nonce_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_n_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_d_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_vid_print(const struct isakmp_gen *,
	u_int, const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_sub0_print(u_char, const struct isakmp_gen *,
	const u_char *,	u_int32_t, u_int32_t, u_int32_t, int);
static const u_char *isakmp_sub_print(u_char, const struct isakmp_gen *,
	const u_char *, u_int32_t, u_int32_t, u_int32_t, int);
static char *numstr(int);
static void safememcpy(void *, const void *, size_t);

#define MAXINITIATORS	20
int ninitiator = 0;
struct {
	cookie_t initiator;
	struct sockaddr_storage iaddr;
	struct sockaddr_storage raddr;
} cookiecache[MAXINITIATORS];

/* protocol id */
static const char *protoidstr[] = {
	NULL, "isakmp", "ipsec-ah", "ipsec-esp", "ipcomp",
};

/* isakmp->np */
static const char *npstr[] = {
	"none", "sa", "p", "t", "ke", "id", "cert", "cr", "hash",
	"sig", "nonce", "n", "d", "vid"
};

/* isakmp->np */
static const u_char *(*npfunc[])(const struct isakmp_gen *, u_int,
		const u_char *, u_int32_t, u_int32_t, u_int32_t, int) = {
	NULL,
	isakmp_sa_print,
	isakmp_p_print,
	isakmp_t_print,
	isakmp_ke_print,
	isakmp_id_print,
	isakmp_cert_print,
	isakmp_cr_print,
	isakmp_hash_print,
	isakmp_sig_print,
	isakmp_nonce_print,
	isakmp_n_print,
	isakmp_d_print,
	isakmp_vid_print,
};

/* isakmp->etype */
static const char *etypestr[] = {
	"none", "base", "ident", "auth", "agg", "inf", NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	"oakley-quick", "oakley-newgroup",
};

#define STR_OR_ID(x, tab) \
	(((x) < sizeof(tab)/sizeof(tab[0]) && tab[(x)])	? tab[(x)] : numstr(x))
#define PROTOIDSTR(x)	STR_OR_ID(x, protoidstr)
#define NPSTR(x)	STR_OR_ID(x, npstr)
#define ETYPESTR(x)	STR_OR_ID(x, etypestr)

#define NPFUNC(x) \
	(((x) < sizeof(npfunc)/sizeof(npfunc[0]) && npfunc[(x)]) \
		? npfunc[(x)] : NULL)

static int
iszero(u_char *p, size_t l)
{
	while (l--) {
		if (*p++)
			return 0;
	}
	return 1;
}

/* find cookie from initiator cache */
static int
cookie_find(cookie_t *in)
{
	int i;

	for (i = 0; i < MAXINITIATORS; i++) {
		if (memcmp(in, &cookiecache[i].initiator, sizeof(*in)) == 0)
			return i;
	}

	return -1;
}

/* record initiator */
/*
static void
cookie_record(cookie_t *in, const u_char *bp2)
{
	int i;
	struct ip *ip;
	struct sockaddr_in *sin;
#ifdef INET6
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *sin6;
#endif

	i = cookie_find(in);
	if (0 <= i) {
		ninitiator = (i + 1) % MAXINITIATORS;
		return;
	}

	ip = (struct ip *)bp2;
	switch (IP_V(ip)) {
	case 4:
		memset(&cookiecache[ninitiator].iaddr, 0,
			sizeof(cookiecache[ninitiator].iaddr));
		memset(&cookiecache[ninitiator].raddr, 0,
			sizeof(cookiecache[ninitiator].raddr));

		sin = (struct sockaddr_in *)&cookiecache[ninitiator].iaddr;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(struct sockaddr_in);
#endif
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, &ip->ip_src, sizeof(ip->ip_src));
		sin = (struct sockaddr_in *)&cookiecache[ninitiator].raddr;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(struct sockaddr_in);
#endif
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, &ip->ip_dst, sizeof(ip->ip_dst));
		break;
#ifdef INET6
	case 6:
		memset(&cookiecache[ninitiator].iaddr, 0,
			sizeof(cookiecache[ninitiator].iaddr));
		memset(&cookiecache[ninitiator].raddr, 0,
			sizeof(cookiecache[ninitiator].raddr));

		ip6 = (struct ip6_hdr *)bp2;
		sin6 = (struct sockaddr_in6 *)&cookiecache[ninitiator].iaddr;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &ip6->ip6_src, sizeof(ip6->ip6_src));
		sin6 = (struct sockaddr_in6 *)&cookiecache[ninitiator].raddr;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &ip6->ip6_dst, sizeof(ip6->ip6_dst));
		break;
#endif
	default:
		return;
	}
	memcpy(&cookiecache[ninitiator].initiator, in, sizeof(*in));
	ninitiator = (ninitiator + 1) % MAXINITIATORS;
}

#define cookie_isinitiator(x, y)	cookie_sidecheck((x), (y), 1)
#define cookie_isresponder(x, y)	cookie_sidecheck((x), (y), 0)
static int
cookie_sidecheck(int i, const u_char *bp2, int initiator)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa;
	struct ip *ip;
	struct sockaddr_in *sin;
#ifdef INET6
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *sin6;
#endif
	int salen;

	memset(&ss, 0, sizeof(ss));
	ip = (struct ip *)bp2;
	switch (IP_V(ip)) {
	case 4:
		sin = (struct sockaddr_in *)&ss;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(struct sockaddr_in);
#endif
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, &ip->ip_src, sizeof(ip->ip_src));
		break;
#ifdef INET6
	case 6:
		ip6 = (struct ip6_hdr *)bp2;
		sin6 = (struct sockaddr_in6 *)&ss;
#ifdef HAVE_SOCKADDR_SA_LEN
		sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &ip6->ip6_src, sizeof(ip6->ip6_src));
		break;
#endif
	default:
		return 0;
	}

	sa = (struct sockaddr *)&ss;
	if (initiator) {
		if (sa->sa_family != ((struct sockaddr *)&cookiecache[i].iaddr)->sa_family)
			return 0;
#ifdef HAVE_SOCKADDR_SA_LEN
		salen = sa->sa_len;
#else
#ifdef INET6
		if (sa->sa_family == AF_INET6)
			salen = sizeof(struct sockaddr_in6);
		else
			salen = sizeof(struct sockaddr);
#else
		salen = sizeof(struct sockaddr);
#endif
#endif
		if (memcmp(&ss, &cookiecache[i].iaddr, salen) == 0)
			return 1;
	} else {
		if (sa->sa_family != ((struct sockaddr *)&cookiecache[i].raddr)->sa_family)
			return 0;
#ifdef HAVE_SOCKADDR_SA_LEN
		salen = sa->sa_len;
#else
#ifdef INET6
		if (sa->sa_family == AF_INET6)
			salen = sizeof(struct sockaddr_in6);
		else
			salen = sizeof(struct sockaddr);
#else
		salen = sizeof(struct sockaddr);
#endif
#endif
		if (memcmp(&ss, &cookiecache[i].raddr, salen) == 0)
			return 1;
	}
	return 0;
}
*/

static int
rawprint(caddr_t loc, size_t len)
{
	static u_char *p;
	size_t i;

	TCHECK2(*loc, len);
	
	p = (u_char *)loc;
	for (i = 0; i < len; i++)
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"%02x", p[i] & 0xff);
	return 1;
trunc:
	return 0;
}

struct attrmap {
	const char *type;
	u_int nvalue;
	const char *value[30];	/*XXX*/
};

static const u_char *
isakmp_attrmap_print(const u_char *p, const u_char *ep,
	const struct attrmap *map, size_t nmap)
{
	u_int16_t *q;
	int totlen;
	u_int32_t t, v;

	q = (u_int16_t *)p;
	if (p[0] & 0x80)
		totlen = 4;
	else
		totlen = 4 + EXTRACT_16BITS(&q[1]);
	if (ep < p + totlen) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|attr]");
		return ep + 1;
	}

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"(");
	t = EXTRACT_16BITS(&q[0]) & 0x7fff;
	if (map && t < nmap && map[t].type)
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"type=%s ", map[t].type);
	else
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"type=#%d ", t);
	if (p[0] & 0x80) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"value=");
		v = EXTRACT_16BITS(&q[1]);
		if (map && t < nmap && v < map[t].nvalue && map[t].value[v])
			sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", map[t].value[v]);
		else
			rawprint((caddr_t)&q[1], 2);
	} else {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"len=%d value=", EXTRACT_16BITS(&q[1]));
		rawprint((caddr_t)&p[4], EXTRACT_16BITS(&q[1]));
	}
	sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
	return p + totlen;
}

static const u_char *
isakmp_attr_print(const u_char *p, const u_char *ep)
{
	u_int16_t *q;
	int totlen;
	u_int32_t t;

	q = (u_int16_t *)p;
	if (p[0] & 0x80)
		totlen = 4;
	else
		totlen = 4 + EXTRACT_16BITS(&q[1]);
	if (ep < p + totlen) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|attr]");
		return ep + 1;
	}

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"(");
	t = EXTRACT_16BITS(&q[0]) & 0x7fff;
	sprintf(&ArgusBuf[strlen(ArgusBuf)],"type=#%d ", t);
	if (p[0] & 0x80) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"value=");
		t = q[1];
		rawprint((caddr_t)&q[1], 2);
	} else {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"len=%d value=", EXTRACT_16BITS(&q[1]));
		rawprint((caddr_t)&p[2], EXTRACT_16BITS(&q[1]));
	}
	sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
	return p + totlen;
}

static const u_char *
isakmp_sa_print(const struct isakmp_gen *ext,
		u_int item_len,
		const u_char *ep, u_int32_t phase, u_int32_t doi0,
		u_int32_t proto0, int depth)
{
	const struct isakmp_pl_sa *p;
	struct isakmp_pl_sa sa;
//	const u_int32_t *q;
	u_int32_t doi, sit, ident;
	const u_char *cp, *np;
	int t;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_SA));

	p = (struct isakmp_pl_sa *)ext;
	TCHECK(*p);
	safememcpy(&sa, ext, sizeof(sa));
	doi = ntohl(sa.doi);
	sit = ntohl(sa.sit);
	if (doi != 1) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=%d", doi);
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," situation=%u", (u_int32_t)ntohl(sa.sit));
		return (u_char *)(p + 1);
	}

	sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=ipsec");
//	q = (u_int32_t *)&sa.sit;
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," situation=");
	t = 0;
	if (sit & 0x01) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"identity");
		t++;
	}
	if (sit & 0x02) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"%ssecrecy", t ? "+" : "");
		t++;
	}
	if (sit & 0x04)
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"%sintegrity", t ? "+" : "");

	np = (u_char *)ext + sizeof(sa);
	if (sit != 0x01) {
		TCHECK2(*(ext + 1), sizeof(ident));
		safememcpy(&ident, ext + 1, sizeof(ident));
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ident=%u", (u_int32_t)ntohl(ident));
		np += sizeof(ident);
	}

	ext = (struct isakmp_gen *)np;
	TCHECK(*ext);

	cp = isakmp_sub_print(ISAKMP_NPTYPE_P, ext, ep, phase, doi, proto0,
		depth);

	return cp;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_SA));
	return NULL;
}

static const u_char *
isakmp_p_print(const struct isakmp_gen *ext, u_int item_len,
	       const u_char *ep, u_int32_t phase, u_int32_t doi0,
	       u_int32_t proto0, int depth)
{
	const struct isakmp_pl_p *p;
	struct isakmp_pl_p prop;
	const u_char *cp;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_P));

	p = (struct isakmp_pl_p *)ext;
	TCHECK(*p);
	safememcpy(&prop, ext, sizeof(prop));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," #%d protoid=%s transform=%d",
		prop.p_no, PROTOIDSTR(prop.prot_id), prop.num_t);
	if (prop.spi_size) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," spi=");
		if (!rawprint((caddr_t)(p + 1), prop.spi_size))
			goto trunc;
	}

	ext = (struct isakmp_gen *)((u_char *)(p + 1) + prop.spi_size);
	TCHECK(*ext);

	cp = isakmp_sub_print(ISAKMP_NPTYPE_T, ext, ep, phase, doi0,
		prop.prot_id, depth);

	return cp;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_P));
	return NULL;
}

static const char *isakmp_p_map[] = {
	NULL, "ike",
};

static const char *ah_p_map[] = {
	NULL, "(reserved)", "md5", "sha", "1des",
	"sha2-256", "sha2-384", "sha2-512",
};

static const char *esp_p_map[] = {
	NULL, "1des-iv64", "1des", "3des", "rc5", "idea", "cast",
	"blowfish", "3idea", "1des-iv32", "rc4", "null", "aes"
};

static const char *ipcomp_p_map[] = {
	NULL, "oui", "deflate", "lzs",
};

const struct attrmap ipsec_t_map[] = {
	{ NULL,	0, { NULL } },
	{ "lifetype", 3, { NULL, "sec", "kb", }, },
	{ "life", 0, { NULL } },
	{ "group desc", 5,	{ NULL, "modp768", "modp1024", "EC2N 2^155",
				  "EC2N 2^185", }, },
	{ "enc mode", 3, { NULL, "tunnel", "transport", }, },
	{ "auth", 5, { NULL, "hmac-md5", "hmac-sha1", "1des-mac", "keyed", }, },
	{ "keylen", 0, { NULL } },
	{ "rounds", 0, { NULL } },
	{ "dictsize", 0, { NULL } },
	{ "privalg", 0, { NULL } },
};

const struct attrmap oakley_t_map[] = {
	{ NULL,	0, { NULL } },
	{ "enc", 8,	{ NULL, "1des", "idea", "blowfish", "rc5",
		 	  "3des", "cast", "aes", }, },
	{ "hash", 7,	{ NULL, "md5", "sha1", "tiger",
			  "sha2-256", "sha2-384", "sha2-512", }, },
	{ "auth", 6,	{ NULL, "preshared", "dss", "rsa sig", "rsa enc",
			  "rsa enc revised", }, },
	{ "group desc", 5,	{ NULL, "modp768", "modp1024", "EC2N 2^155",
				  "EC2N 2^185", }, },
	{ "group type", 4,	{ NULL, "MODP", "ECP", "EC2N", }, },
	{ "group prime", 0, { NULL } },
	{ "group gen1", 0, { NULL } },
	{ "group gen2", 0, { NULL } },
	{ "group curve A", 0, { NULL } },
	{ "group curve B", 0, { NULL } },
	{ "lifetype", 3,	{ NULL, "sec", "kb", }, },
	{ "lifeduration", 0, { NULL } },
	{ "prf", 0, { NULL } },
	{ "keylen", 0, { NULL } },
	{ "field", 0, { NULL } },
	{ "order", 0, { NULL } },
};

static const u_char *
isakmp_t_print(const struct isakmp_gen *ext, u_int item_len,
	const u_char *ep, u_int32_t phase, u_int32_t doi,
	u_int32_t proto, int depth)
{
	const struct isakmp_pl_t *p;
	struct isakmp_pl_t t;
	const u_char *cp;
	const char *idstr;
	const struct attrmap *map;
	size_t nmap;
	const u_char *ep2;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_T));

	p = (struct isakmp_pl_t *)ext;
	TCHECK(*p);
	safememcpy(&t, ext, sizeof(t));

	switch (proto) {
	case 1:
		idstr = STR_OR_ID(t.t_id, isakmp_p_map);
		map = oakley_t_map;
		nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
		break;
	case 2:
		idstr = STR_OR_ID(t.t_id, ah_p_map);
		map = ipsec_t_map;
		nmap = sizeof(ipsec_t_map)/sizeof(ipsec_t_map[0]);
		break;
	case 3:
		idstr = STR_OR_ID(t.t_id, esp_p_map);
		map = ipsec_t_map;
		nmap = sizeof(ipsec_t_map)/sizeof(ipsec_t_map[0]);
		break;
	case 4:
		idstr = STR_OR_ID(t.t_id, ipcomp_p_map);
		map = ipsec_t_map;
		nmap = sizeof(ipsec_t_map)/sizeof(ipsec_t_map[0]);
		break;
	default:
		idstr = NULL;
		map = NULL;
		nmap = 0;
		break;
	}

	if (idstr)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," #%d id=%s ", t.t_no, idstr);
	else
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," #%d id=%d ", t.t_no, t.t_id);
	cp = (u_char *)(p + 1);
	ep2 = (u_char *)p + item_len;
	while (cp < ep && cp < ep2) {
		if (map && nmap) {
			cp = isakmp_attrmap_print(cp, (ep < ep2) ? ep : ep2,
				map, nmap);
		} else
			cp = isakmp_attr_print(cp, (ep < ep2) ? ep : ep2);
	}
	if (ep < ep2)
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
	return cp;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_T));
	return NULL;
}

static const u_char *
isakmp_ke_print(const struct isakmp_gen *ext, u_int item_len,
		const u_char *ep, u_int32_t phase, u_int32_t doi,
		u_int32_t proto, int depth)
{
	struct isakmp_gen e;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_KE));

	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," key len=%d", ntohs(e.len) - 4);
	if (2 < ArgusParser->vflag && 4 < ntohs(e.len)) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (u_char *)ext + ntohs(e.len);
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_KE));
	return NULL;
}

static const u_char *
isakmp_id_print(const struct isakmp_gen *ext, u_int item_len,
		const u_char *ep, u_int32_t phase, u_int32_t doi,
		u_int32_t proto, int depth)
{
#define USE_IPSECDOI_IN_PHASE1	1
	const struct isakmp_pl_id *p;
	struct isakmp_pl_id id;
	static const char *idtypestr[] = {
		"IPv4", "IPv4net", "IPv6", "IPv6net",
	};
	static const char *ipsecidtypestr[] = {
		NULL, "IPv4", "FQDN", "user FQDN", "IPv4net", "IPv6",
		"IPv6net", "IPv4range", "IPv6range", "ASN1 DN", "ASN1 GN",
		"keyid",
	};
	int len;
	const u_char *data;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_ID));

	p = (struct isakmp_pl_id *)ext;
	TCHECK(*p);
	safememcpy(&id, ext, sizeof(id));
	if (sizeof(*p) < item_len) {
		data = (u_char *)(p + 1);
		len = item_len - sizeof(*p);
	} else {
		data = NULL;
		len = 0;
	}

#if 0 /*debug*/
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [phase=%d doi=%d proto=%d]", phase, doi, proto);
#endif
	switch (phase) {
#ifndef USE_IPSECDOI_IN_PHASE1
	case 1:
#endif
	default:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," idtype=%s", STR_OR_ID(id.d.id_type, idtypestr));
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi_data=%u",
			(u_int32_t)(ntohl(id.d.doi_data) & 0xffffff));
		break;

#ifdef USE_IPSECDOI_IN_PHASE1
	case 1:
#endif
	case 2:
	    {
		const struct ipsecdoi_id *p;
		struct ipsecdoi_id id;
		struct protoent *pe;

		p = (struct ipsecdoi_id *)ext;
		TCHECK(*p);
		safememcpy(&id, ext, sizeof(id));
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," idtype=%s", STR_OR_ID(id.type, ipsecidtypestr));
		if (id.proto_id) {
#ifndef WIN32
			setprotoent(1);
#endif /* WIN32 */
			pe = getprotobynumber(id.proto_id);
			if (pe)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," protoid=%s", pe->p_name);
#ifndef WIN32
			endprotoent();
#endif /* WIN32 */
		} else {
			/* it DOES NOT mean IPPROTO_IP! */
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," protoid=%s", "0");
		}
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," port=%d", ntohs(id.port));
		if (!len)
			break;
		if (data == NULL)
			goto trunc;
		TCHECK2(*data, len);
		switch (id.type) {
		case IPSECDOI_ID_IPV4_ADDR:
			if (len < 4)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 4]", len);
			else
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s", len, ipaddr_string(data));
			len = 0;
			break;
		case IPSECDOI_ID_FQDN:
		case IPSECDOI_ID_USER_FQDN:
		    {
			int i;
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d ", len);
			for (i = 0; i < len; i++)
			   sprintf(&ArgusBuf[strlen(ArgusBuf)],"%c", data[i]);
			len = 0;
			break;
		    }
		case IPSECDOI_ID_IPV4_ADDR_SUBNET:
		    {
			const u_char *mask;
			if (len < 8)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 8]", len);
			else {
				mask = data + sizeof(struct in_addr);
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s/%u.%u.%u.%u", len,
					ipaddr_string(data),
					mask[0], mask[1], mask[2], mask[3]);
			}
			len = 0;
			break;
		    }
#ifdef INET6
		case IPSECDOI_ID_IPV6_ADDR:
			if (len < 16)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 16]", len);
			else
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s", len, ip6addr_string(data));
			len = 0;
			break;
		case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		    {
			const u_int32_t *mask;
			if (len < 20)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 20]", len);
			else {
				mask = (u_int32_t *)(data + sizeof(struct in6_addr));
				/*XXX*/
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s/0x%08x%08x%08x%08x", len,
					ip6addr_string(data),
					mask[0], mask[1], mask[2], mask[3]);
			}
			len = 0;
			break;
		    }
#endif /*INET6*/
		case IPSECDOI_ID_IPV4_ADDR_RANGE:
			if (len < 8)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 8]", len);
			else {
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s-%s", len,
					ipaddr_string(data),
					ipaddr_string(data + sizeof(struct in_addr)));
			}
			len = 0;
			break;
#ifdef INET6
		case IPSECDOI_ID_IPV6_ADDR_RANGE:
			if (len < 32)
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d [bad: < 32]", len);
			else {
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d %s-%s", len,
					ip6addr_string(data),
					ip6addr_string(data + sizeof(struct in6_addr)));
			}
			len = 0;
			break;
#endif /*INET6*/
		case IPSECDOI_ID_DER_ASN1_DN:
		case IPSECDOI_ID_DER_ASN1_GN:
		case IPSECDOI_ID_KEY_ID:
			break;
		}
		break;
	    }
	}
	if (data && len) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", len);
		if (2 < ArgusParser->vflag) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
			if (!rawprint((caddr_t)data, len))
				goto trunc;
		}
	}
	return (u_char *)ext + item_len;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_ID));
	return NULL;
}

static const u_char *
isakmp_cert_print(const struct isakmp_gen *ext, u_int item_len,
		  const u_char *ep, u_int32_t phase,
		  u_int32_t doi0,
		  u_int32_t proto0, int depth)
{
	const struct isakmp_pl_cert *p;
	struct isakmp_pl_cert cert;
	static const char *certstr[] = {
		"none",	"pkcs7", "pgp", "dns",
		"x509sign", "x509ke", "kerberos", "crl",
		"arl", "spki", "x509attr",
	};

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_CERT));

	p = (struct isakmp_pl_cert *)ext;
	TCHECK(*p);
	safememcpy(&cert, ext, sizeof(cert));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", item_len - 4);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", STR_OR_ID((cert.encode), certstr));
	if (2 < ArgusParser->vflag && 4 < item_len) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), item_len - 4))
			goto trunc;
	}
	return (u_char *)ext + item_len;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_CERT));
	return NULL;
}

static const u_char *
isakmp_cr_print(const struct isakmp_gen *ext, u_int item_len,
		const u_char *ep, u_int32_t phase, u_int32_t doi0,
		u_int32_t proto0, int depth)
{
	const struct isakmp_pl_cert *p;
	struct isakmp_pl_cert cert;
	static const char *certstr[] = {
		"none",	"pkcs7", "pgp", "dns",
		"x509sign", "x509ke", "kerberos", "crl",
		"arl", "spki", "x509attr",
	};

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_CR));

	p = (struct isakmp_pl_cert *)ext;
	TCHECK(*p);
	safememcpy(&cert, ext, sizeof(cert));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", item_len - 4);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", STR_OR_ID((cert.encode), certstr));
	if (2 < ArgusParser->vflag && 4 < item_len) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), item_len - 4))
			goto trunc;
	}
	return (u_char *)ext + item_len;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_CR));
	return NULL;
}

static const u_char *
isakmp_hash_print(const struct isakmp_gen *ext, u_int item_len,
		  const u_char *ep, u_int32_t phase, u_int32_t doi,
		  u_int32_t proto, int depth)
{
	struct isakmp_gen e;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_HASH));

	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", ntohs(e.len) - 4);
	if (2 < ArgusParser->vflag && 4 < ntohs(e.len)) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (u_char *)ext + ntohs(e.len);
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_HASH));
	return NULL;
}

static const u_char *
isakmp_sig_print(const struct isakmp_gen *ext, u_int item_len,
		 const u_char *ep, u_int32_t phase, u_int32_t doi,
		 u_int32_t proto, int depth)
{
	struct isakmp_gen e;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_SIG));

	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", ntohs(e.len) - 4);
	if (2 < ArgusParser->vflag && 4 < ntohs(e.len)) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (u_char *)ext + ntohs(e.len);
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_SIG));
	return NULL;
}

static const u_char *
isakmp_nonce_print(const struct isakmp_gen *ext,
		   u_int item_len,
		   const u_char *ep,
		   u_int32_t phase, u_int32_t doi,
		   u_int32_t proto, int depth)
{
	struct isakmp_gen e;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_NONCE));

	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," n len=%d", ntohs(e.len) - 4);
	if (2 < ArgusParser->vflag && 4 < ntohs(e.len)) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (u_char *)ext + ntohs(e.len);
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_NONCE));
	return NULL;
}

static const u_char *
isakmp_n_print(const struct isakmp_gen *ext, u_int item_len,
	const u_char *ep, u_int32_t phase, u_int32_t doi0,
	u_int32_t proto0, int depth)
{
	struct isakmp_pl_n *p, n;
	const u_char *cp;
	u_char *ep2;
	u_int32_t doi;
	u_int32_t proto;
	static const char *notify_error_str[] = {
		NULL,				"INVALID-PAYLOAD-TYPE",
		"DOI-NOT-SUPPORTED",		"SITUATION-NOT-SUPPORTED",
		"INVALID-COOKIE",		"INVALID-MAJOR-VERSION",
		"INVALID-MINOR-VERSION",	"INVALID-EXCHANGE-TYPE",
		"INVALID-FLAGS",		"INVALID-MESSAGE-ID",
		"INVALID-PROTOCOL-ID",		"INVALID-SPI",
		"INVALID-TRANSFORM-ID",		"ATTRIBUTES-NOT-SUPPORTED",
		"NO-PROPOSAL-CHOSEN",		"BAD-PROPOSAL-SYNTAX",
		"PAYLOAD-MALFORMED",		"INVALID-KEY-INFORMATION",
		"INVALID-ID-INFORMATION",	"INVALID-CERT-ENCODING",
		"INVALID-CERTIFICATE",		"CERT-TYPE-UNSUPPORTED",
		"INVALID-CERT-AUTHORITY",	"INVALID-HASH-INFORMATION",
		"AUTHENTICATION-FAILED",	"INVALID-SIGNATURE",
		"ADDRESS-NOTIFICATION",		"NOTIFY-SA-LIFETIME",
		"CERTIFICATE-UNAVAILABLE",	"UNSUPPORTED-EXCHANGE-TYPE",
		"UNEQUAL-PAYLOAD-LENGTHS",
	};
	static const char *ipsec_notify_error_str[] = {
		"RESERVED",
	};
	static const char *notify_status_str[] = {
		"CONNECTED",
	};
	static const char *ipsec_notify_status_str[] = {
		"RESPONDER-LIFETIME",		"REPLAY-STATUS",
		"INITIAL-CONTACT",
	};
/* NOTE: these macro must be called with x in proper range */

/* 0 - 8191 */
#define NOTIFY_ERROR_STR(x) \
	STR_OR_ID((x), notify_error_str)

/* 8192 - 16383 */
#define IPSEC_NOTIFY_ERROR_STR(x) \
	STR_OR_ID((u_int)((x) - 8192), ipsec_notify_error_str)

/* 16384 - 24575 */
#define NOTIFY_STATUS_STR(x) \
	STR_OR_ID((u_int)((x) - 16384), notify_status_str)

/* 24576 - 32767 */
#define IPSEC_NOTIFY_STATUS_STR(x) \
	STR_OR_ID((u_int)((x) - 24576), ipsec_notify_status_str)

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_N));

	p = (struct isakmp_pl_n *)ext;
	TCHECK(*p);
	safememcpy(&n, ext, sizeof(n));
	doi = ntohl(n.doi);
	proto = n.prot_id;
	if (doi != 1) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=%d", doi);
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," proto=%d", proto);
		if (ntohs(n.type) < 8192)
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", NOTIFY_ERROR_STR(ntohs(n.type)));
		else if (ntohs(n.type) < 16384)
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", numstr(ntohs(n.type)));
		else if (ntohs(n.type) < 24576)
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", NOTIFY_STATUS_STR(ntohs(n.type)));
		else
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", numstr(ntohs(n.type)));
		if (n.spi_size) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," spi=");
			if (!rawprint((caddr_t)(p + 1), n.spi_size))
				goto trunc;
		}
		return (u_char *)(p + 1) + n.spi_size;
	}

	sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=ipsec");
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," proto=%s", PROTOIDSTR(proto));
	if (ntohs(n.type) < 8192)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", NOTIFY_ERROR_STR(ntohs(n.type)));
	else if (ntohs(n.type) < 16384)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", IPSEC_NOTIFY_ERROR_STR(ntohs(n.type)));
	else if (ntohs(n.type) < 24576)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", NOTIFY_STATUS_STR(ntohs(n.type)));
	else if (ntohs(n.type) < 32768)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", IPSEC_NOTIFY_STATUS_STR(ntohs(n.type)));
	else
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," type=%s", numstr(ntohs(n.type)));
	if (n.spi_size) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," spi=");
		if (!rawprint((caddr_t)(p + 1), n.spi_size))
			goto trunc;
	}

	cp = (u_char *)(p + 1) + n.spi_size;
	ep2 = (u_char *)p + item_len;

	if (cp < ep) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," orig=(");
		switch (ntohs(n.type)) {
		case IPSECDOI_NTYPE_RESPONDER_LIFETIME:
		    {
			const struct attrmap *map = oakley_t_map;
			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
			while (cp < ep && cp < ep2) {
				cp = isakmp_attrmap_print(cp,
					(ep < ep2) ? ep : ep2, map, nmap);
			}
			break;
		    }
		case IPSECDOI_NTYPE_REPLAY_STATUS:
			sprintf(&ArgusBuf[strlen(ArgusBuf)],"replay detection %sabled",
				(*(u_int32_t *)cp) ? "en" : "dis");
			break;
		case ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN:
			if (isakmp_sub_print(ISAKMP_NPTYPE_SA,
			    (struct isakmp_gen *)cp, ep, phase, doi, proto,
			    depth) == NULL)
				return NULL;
			break;
		default:
			/* NULL is dummy */
			isakmp_print(cp, item_len - sizeof(*p) - n.spi_size);
		}
		sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
	}
	return (u_char *)ext + item_len;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_N));
	return NULL;
}

static const u_char *
isakmp_d_print(const struct isakmp_gen *ext, u_int item_len,
	       const u_char *ep, u_int32_t phase, u_int32_t doi0,
	       u_int32_t proto0, int depth)
{
	const struct isakmp_pl_d *p;
	struct isakmp_pl_d d;
	const u_int8_t *q;
	u_int32_t doi;
	u_int32_t proto;
	int i;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_D));

	p = (struct isakmp_pl_d *)ext;
	TCHECK(*p);
	safememcpy(&d, ext, sizeof(d));
	doi = ntohl(d.doi);
	proto = d.prot_id;
	if (doi != 1) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=%u", doi);
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," proto=%u", proto);
	} else {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," doi=ipsec");
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," proto=%s", PROTOIDSTR(proto));
	}
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," spilen=%u", d.spi_size);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," nspi=%u", ntohs(d.num_spi));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," spi=");
	q = (u_int8_t *)(p + 1);
	for (i = 0; i < ntohs(d.num_spi); i++) {
		if (i != 0)
			sprintf(&ArgusBuf[strlen(ArgusBuf)],",");
		if (!rawprint((caddr_t)q, d.spi_size))
			goto trunc;
		q += d.spi_size;
	}
	return q;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_D));
	return NULL;
}

static const u_char *
isakmp_vid_print(const struct isakmp_gen *ext,
		 u_int item_len, const u_char *ep,
		 u_int32_t phase, u_int32_t doi,
		 u_int32_t proto, int depth)
{
	struct isakmp_gen e;

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s:", NPSTR(ISAKMP_NPTYPE_VID));

	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," len=%d", ntohs(e.len) - 4);
	if (2 < ArgusParser->vflag && 4 < ntohs(e.len)) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
		if (!rawprint((caddr_t)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (u_char *)ext + ntohs(e.len);
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(ISAKMP_NPTYPE_VID));
	return NULL;
}

static const u_char *
isakmp_sub0_print(u_char np, const struct isakmp_gen *ext, const u_char *ep,
	u_int32_t phase, u_int32_t doi, u_int32_t proto, int depth)
{
	const u_char *cp;
	struct isakmp_gen e;
	u_int item_len;

	cp = (u_char *)ext;
	TCHECK(*ext);
	safememcpy(&e, ext, sizeof(e));

	/*
	 * Since we can't have a payload length of less than 4 bytes,
	 * we need to bail out here if the generic header is nonsensical
	 * or truncated, otherwise we could loop forever processing
	 * zero-length items or otherwise misdissect the packet.
	 */
	item_len = ntohs(e.len);
	if (item_len <= 4)
		return NULL;

	if (NPFUNC(np)) {
		/*
		 * XXX - what if item_len is too short, or too long,
		 * for this payload type?
		 */
		cp = (*npfunc[np])(ext, item_len, ep, phase, doi, proto, depth);
	} else {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", NPSTR(np));
		cp += item_len;
	}

	return cp;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|isakmp]");
	return NULL;
}

static const u_char *
isakmp_sub_print(u_char np, const struct isakmp_gen *ext, const u_char *ep,
	u_int32_t phase, u_int32_t doi, u_int32_t proto, int depth)
{
	const u_char *cp;
	int i;
	struct isakmp_gen e;

	cp = (const u_char *)ext;

	while (np) {
		TCHECK(*ext);
		
		safememcpy(&e, ext, sizeof(e));

		TCHECK2(*ext, ntohs(e.len));

		depth++;
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n");
		for (i = 0; i < depth; i++)
			sprintf(&ArgusBuf[strlen(ArgusBuf)],"    ");
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"(");
		cp = isakmp_sub0_print(np, ext, ep, phase, doi, proto, depth);
		sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
		depth--;

		if (cp == NULL) {
			/* Zero-length subitem */
			return NULL;
		}

		np = e.np;
		ext = (struct isakmp_gen *)cp;
	}
	return cp;
trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(np));
	return NULL;
}

static char *
numstr(int x)
{
	static char buf[20];
	snprintf(buf, sizeof(buf), "#%d", x);
	return buf;
}

/*
 * some compiler tries to optimize memcpy(), using the alignment constraint
 * on the argument pointer type.  by using this function, we try to avoid the
 * optimization.
 */
static void
safememcpy(void *p, const void *q, size_t l)
{
	memcpy(p, q, l);
}

char *
isakmp_print(const u_char *bp, u_int length)
{
	const struct isakmp *p;
	struct isakmp base;
	const u_char *ep;
	u_char np;
	int i;
	int phase;
	int major, minor;

	p = (const struct isakmp *)bp;
	ep = snapend;

	if ((struct isakmp *)ep < p + 1) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|isakmp]");
		return ArgusBuf;
	}

	safememcpy(&base, p, sizeof(base));

	sprintf(&ArgusBuf[strlen(ArgusBuf)],"isakmp");
	if (ArgusParser->vflag) {
		major = (base.vers & ISAKMP_VERS_MAJOR)
				>> ISAKMP_VERS_MAJOR_SHIFT;
		minor = (base.vers & ISAKMP_VERS_MINOR)
				>> ISAKMP_VERS_MINOR_SHIFT;
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," %d.%d", major, minor);
	}

	if (ArgusParser->vflag) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," msgid ");
		rawprint((caddr_t)&base.msgid, sizeof(base.msgid));
	}

	if (1 < ArgusParser->vflag) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," cookie ");
		rawprint((caddr_t)&base.i_ck, sizeof(base.i_ck));
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"->");
		rawprint((caddr_t)&base.r_ck, sizeof(base.r_ck));
	}
	sprintf(&ArgusBuf[strlen(ArgusBuf)],":");

	phase = (*(u_int32_t *)base.msgid == 0) ? 1 : 2;
	if (phase == 1)
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," phase %d", phase);
	else
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," phase %d/others", phase);

	i = cookie_find(&base.i_ck);
	if (i < 0) {
		if (iszero((u_char *)&base.r_ck, sizeof(base.r_ck))) {
			/* the first packet */
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," I");
/*
			if (bp2)
				cookie_record(&base.i_ck, bp2);
*/
		} else
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," ?");
	} else {
/*
		if (bp2 && cookie_isinitiator(i, bp2))
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," I");
		else if (bp2 && cookie_isresponder(i, bp2))
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," R");
		else
*/
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," ?");
	}

	sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ETYPESTR(base.etype));
	if (base.flags) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"[%s%s]", base.flags & ISAKMP_FLAG_E ? "E" : "",
			base.flags & ISAKMP_FLAG_C ? "C" : "");
	}

	if (ArgusParser->vflag) {
		const struct isakmp_gen *ext;
//		int nparen;

#define CHECKLEN(p, np) \
		if (ep < (u_char *)(p)) {				\
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|%s]", NPSTR(np));			\
			goto done;					\
		}

		sprintf(&ArgusBuf[strlen(ArgusBuf)],":");

		/* regardless of phase... */
		if (base.flags & ISAKMP_FLAG_E) {
			/*
			 * encrypted, nothing we can do right now.
			 * we hope to decrypt the packet in the future...
			 */
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [encrypted %s]", NPSTR(base.np));
			goto done;
		}

//		nparen = 0;
		CHECKLEN(p + 1, base.np)

		np = base.np;
		ext = (struct isakmp_gen *)(p + 1);
		isakmp_sub_print(np, ext, ep, phase, 0, 0, 0);
	}

done:
	if (ArgusParser->vflag) {
		if (ntohl(base.len) != length) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," (len mismatch: isakmp %u/ip %u)",
				(u_int32_t)ntohl(base.len), length);
		}
	}
	return ArgusBuf;
}

char *
isakmp_rfc3948_print(const u_char *bp, u_int length)
{
/*
	const u_char *ep;
	ep = snapend;
*/
	if(length == 1 && bp[0]==0xff) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"isakmp-nat-keep-alive");
		return ArgusBuf;
	}

	if(length < 4) {
		goto trunc;
	}

	/*
	 * see if this is an IKE packet
	 */
	if(bp[0]==0 && bp[1]==0 && bp[2]==0 && bp[3]==0) {
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"NONESP-encap: ");
		isakmp_print(bp+4, length-4);
		return ArgusBuf;
	}

	/* must be an ESP packet */
	{
/*
  		int nh = 0, enh = 0, padlen = 0;
		int advance = 0;
*/
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"UDP-encap: ");
/*
		advance = esp_print(ndo, bp, length, bp2, &enh, &padlen);

		if (advance <= 0)
			return ArgusBuf;

		bp += advance;

		length -= advance + padlen;
		nh = enh & 0xff;

		ip_print_inner(ndo, bp, length, nh, bp2);
*/
		return ArgusBuf;
	}

trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|isakmp]");
	return ArgusBuf;
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */


  

