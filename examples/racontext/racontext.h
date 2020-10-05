#ifndef __CLIENTS_RACONTEXT_H
# define __CLIENTS_RACONTEXT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <sys/time.h>
# include <sys/socket.h>
# include <net/ethernet.h>
# include <stdbool.h>
# include <limits.h>
# include <uuid/uuid.h>
# include "argus_util.h"
# include "argus_mysql.h" /* move sql things to other header later */
# include "argus_parser.h"
# include "bsd/sys/tree.h"

#ifndef ETH_ALEN
# define ETH_ALEN ETHER_ADDR_LEN
#endif

/* XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/infX\0 */
# define RCT_SIDINF_LEN_MAX		42

# define RACONTEXT_MIN_MATCHING_SCORE	1.0
# define RACONTEXT_VALUE_NAMELEN	64
# define RACONTEXT_OCCURRENCES_NORM_THRESHOLD	0.01
# define RACONTEXT_DISTINCT_TYPES_THRESHOLD	4
static const char * const contexts_table_name = "testdata.contexts";
static const char * const index_table_name = "testdata.context_index";

typedef struct _configuration_t {
   unsigned int silence_duration_sec;
   unsigned int context_min_duration_sec;
   char *database_uri_dhcp;
   char *database_uri_ctx;
   struct ether_addr *clientmac;
} configuration_t;

enum RacontextAttribute_e {
   CTX_ATTRIB_BSSID = 0,
   CTX_ATTRIB_DHCP_SERVER_MAC,
   CTX_ATTRIB_NEXT_HOP_MAC,
   CTX_ATTRIB_SLAAC_PREFIX,
   CTX_ATTRIB_DHCP_DNS_SERVER,
   CTX_ATTRIB_DHCP_DNS_DOMAIN,
   CTX_ATTRIB_DHCP_NEXTHOP,
   CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME,
   CTX_ATTRIB_IGMP_QUERIER_MAC,
   CTX_ATTRIB_IGMP_QUERIER_ADDRESS,
   CTX_ATTRIB_MCAST_SOURCE_MAC,
   CTX_ATTRIB_BCAST_SOURCE_MAC,
   CTX_ATTRIB_MCAST_DEST_MAC,
   NUM_CTX_ATTRIB,
};

struct racontext_attribute;
RB_HEAD(racontext_attr_tree, racontext_attribute);

struct racontext_attribute {
   RB_ENTRY(racontext_attribute) tree;
   union {
      unsigned char l2addr[16];
      struct sockaddr_in6 l3addr;
      char *name;
   } value_un;
   /* --- cacheline 1 boundary (64 bytes) --- */
   unsigned int occurrences;	/* no. times this value seen in this dataset */
   float occurrences_norm;	/* normalized for context duration */
   int32_t attrib_num;
   uint8_t prefixlen;
};



struct known_context_match;
RB_HEAD(known_context_tree, known_context_match);

/* We will need an array size that is a multiple of 16 bytes
 * loading data into vector types.  For arrays of 4-byte elements:
 */
#define NUM_CTX_ATTRIB_MULT4	(((NUM_CTX_ATTRIB+3)>>2)<<2)

/* attr_match_counts needs to be allocated on 16 byte boundary,
 * so it's probably easiest to keep it at the beginning of the
 * structure.  Keep in mind that it's size will change as attribute
 * types are added or removed.
 */
struct known_context_match {
   unsigned int attr_match_counts[NUM_CTX_ATTRIB_MULT4]; /* from SQL */
        /* --- cacheline 1 boundary (64 bytes) --- */
   RB_ENTRY(known_context_match) tree;
   uuid_t cid;			/* context ID */
   double score;
   unsigned distict_attr_types;	/* from SQL */
   unsigned total_weight;	/* from SQL */

   /* weighted_total = SIGMA(weights[i] * attr_match_counts[i])
    * total_context_weight = the sum of weights for each attribute in a
    *                        known context
    *            weighted_total
    * avg =   --------------------
    *         total_context_weight
    *
    * score = avg * #_distinct_attribute_types_matched
    *
    * 0.0 < agv <= 1.0
    * 0.0: nothing matched
    * 1.0: all attributes of known context matched
    *
    * 0.0 < score <= largest count of known context attributes
    *
    * #_distinct_attribute_types_matched is known at the time of the
    * SQL query (number of rows returned).
    *
    * "largest count of known context attributes" does not need to be known
    * because we will just look for the largest value.  However, it can be
    * limited during new context creation, if needed.
    */
};



struct racontext;
RB_HEAD(racontext_tree, racontext);

struct racontext {
   RB_ENTRY(racontext) tree;
   struct timeval stime; /* always usec resolution */
   struct timeval ltime; /* always usec resolution */
        /* --- cacheline 1 boundary (64 bytes) --- */
   struct racontext_attr_tree *attrs;
   /* number of occurrences of each attribute by type */
   unsigned int per_attr_totals[NUM_CTX_ATTRIB];
   int source;
        /* --- cacheline 2 boundary (128 bytes) --- */
   /* en element in the match tree, non-NULL if match found. */
   struct known_context_match *match;
   struct known_context_tree known_contexts;
};



static inline void
RacontextIncrPerAttrTotal(struct racontext *ctx, int32_t attrib_num)
{
   if (ctx->per_attr_totals[attrib_num] < UINT_MAX)
      ctx->per_attr_totals[attrib_num]++;
}

/* per-(sid,inf) contexts */
struct RacontextTree {
   /* This entire tree can be added to a sid_tree */
   RB_ENTRY(RacontextTree) entry; /* TODO: rename this to tree */
   struct racontext_tree head;
   char *srcidstr; /* the result of ArgusPrintSourceID() */
};

RB_HEAD(sid_tree, RacontextTree);

/* no structure around sid_tree -- currently there's no reason to
 * have multiple trees or distinguish between trees.
 */

struct racontext *RacontextAlloc(void);
void RacontextFree(struct racontext *);

struct RacontextTree *
RacontextTreeAlloc(struct ArgusParserStruct *parser,
                   struct ArgusRecordStruct *argus);
int RacontextTreeInsert(struct RacontextTree *rct,
                        const struct timeval * const startime,
                        const struct timeval * const lasttime,
                        const configuration_t * const config,
                        struct racontext **newctx);
int RacontextTreeAppend(struct RacontextTree *rct,
                        struct ArgusRecordStruct *argus,
                        const configuration_t * const config,
                        struct racontext **newctx);
int RacontextTreeRemove(struct RacontextTree *rct,
                        struct racontext *ctx);
struct racontext * RacontextTreeFind(struct RacontextTree *rct, struct timeval *when);
void RacontextTreeFree(struct RacontextTree *rct);
bool RacontextAttrTreeEmpty(struct racontext_attr_tree *rat);
int RacontextTreePullup(struct RacontextTree *rct, void *arg);
void RacontextTreeDump(struct RacontextTree *rct);
int RacontextTreeScore(const struct ArgusParserStruct * const parser,
                       MYSQL *mysql, struct RacontextTree *rct);


typedef int (*sid_tree_callback)(struct RacontextTree *, void *);
struct sid_tree *SidtreeAlloc(void);
int SidtreeInsert(struct sid_tree *t, struct RacontextTree *e);
int SidtreeFind(struct sid_tree *t, const char * const srcidstr,
                struct RacontextTree **target);
int SidtreeFindByRecordStruct(struct sid_tree *t, struct RacontextTree **target,
                              struct ArgusParserStruct *parser,
                              struct ArgusRecordStruct *argus);
int SidtreeRemove(struct sid_tree *t, struct RacontextTree *e);
void SidtreeFree(struct sid_tree *t);
int SidtreeForeach(struct sid_tree *t, sid_tree_callback cb, void *arg);
void SidtreeDump(struct sid_tree *t);
int SidtreeScore(const struct ArgusParserStruct * const parser, MYSQL *mysql,
                 struct sid_tree *t);


/* racontext_attribute.c */
void RacontextAttrFree(struct racontext_attribute *a, bool deep);
struct racontext_attr_tree *RacontextAttrTreeAlloc(void);
int RacontextAttrTreeInsert(struct racontext_attr_tree *rat,
                            const struct racontext_attribute *attr,
                            bool deepcopy);
int RacontextAttrTreeRemove(struct racontext_attr_tree *rat,
                            struct racontext_attribute *attr);
struct racontext_attribute *
RacontextAttrTreeFind(struct racontext_attr_tree *rat,
                      struct racontext_attribute *exemplar);
void RacontextAttrTreeFree(struct racontext_attr_tree *rat);
char *RacontextAttrName(const struct racontext_attribute * const attr);
char *RacontextAttrValuePrint(const struct racontext_attribute * const a);
int RacontextAttrTreeDump(struct racontext_attr_tree *rat);
int RacontextAttrTreeSqlWhere(struct racontext_attr_tree * rat,
                              char *buf, size_t *used, size_t *remain);
struct racontext_attribute *RacontextAttrTreeFirst(struct racontext_attr_tree *);
struct racontext_attribute *RacontextAttrTreeNext(struct racontext_attribute *);


/* racontext_attribute_weights.c */
unsigned int RacontextAttributeWeight(int32_t attrib_num);

/* racontext_known_context_tree.c */
void KnownContextTreeInit(struct known_context_tree *kct);
struct known_context_match *KnownContextMatchAlloc(void);
void KnownContextMatchFree(struct known_context_match *kcm);
void KnownContextMatchDump(const struct known_context_match * const kcm);
void KnownContextDump(const struct known_context_match * const kcm);
int KnownContextTreeInsert(struct known_context_tree *kct, uuid_t cid,
                           struct known_context_match **kcm_out);
int KnownContextTreeFind(struct known_context_tree *kct, uuid_t cid,
                         struct known_context_match **kcm_out);
void KnownContextTreeFree(struct known_context_tree *kct);
struct known_context_match *KnownContextTreeFirst(struct known_context_tree *kcm);
struct known_context_match *KnownContextTreeNext(struct known_context_match *kcm);
void KnownContextTreeDump(struct known_context_tree *kct);

/* racontext_known_context_calc.c */
unsigned long long RacontextTotalWeightCalc(unsigned int *counts);
int RacontextKnownContextCalc(struct racontext *ctx);

/* racontext_query_index.c */
int RacontextQueryIndex(MYSQL *mysql, struct racontext *ctx);

/* racontext_attribute_normalize.c */
unsigned int RacontextNormalizeAttributeOccurences(struct racontext *ctx,
                                                   unsigned int *counts);

#endif
