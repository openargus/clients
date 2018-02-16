/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2017 QoSient, LLC
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
 */

#ifndef __RABOOTP_PATRICIA_TREE_H
# define __RABOOTP_PATRICIA_TREE_H

# include "argus_parser.h"
# include "rabootp.h"

typedef int (*RabootpPatriciaTreeCallback)(struct RaAddressStruct *, void *);

int
RabootpPatriciaTreeUpdate(const struct ArgusDhcpStruct * const,
                          struct ArgusDhcpStruct *,
                          struct ArgusParserStruct *);

int
RabootpPatriciaTreeForeach(struct RaAddressStruct *,
                           RabootpPatriciaTreeCallback,
                           void *);

struct RaAddressStruct *
RabootpPatriciaTreeFind(const unsigned int * const,
                        unsigned char masklen,
                        struct ArgusParserStruct *);

int
RabootpPatriciaTreeRemoveLease(const unsigned int * const,
                               const unsigned char * const,
                               size_t,
                               const struct timeval * const,
                               const struct ArgusDhcpStruct * const,
                               struct ArgusParserStruct *);

int
RabootpPatriciaTreeSearch(const struct in_addr * const,
                          unsigned char masklen,
                          const struct timeval * const,
                          const struct timeval * const,
                          struct ArgusDhcpIntvlNode *,
                          size_t);
#endif
