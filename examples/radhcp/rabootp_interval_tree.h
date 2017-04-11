#ifndef __RABOOTP_INTERVAL_TREE_H
# define __RABOOTP_INTERVAL_TREE_H
# include <sys/time.h>
# include "argus_config.h"
# include "bsd/sys/tree.h"
# include "rabootp.h"

# ifndef timersub
#  define timersub(tvp, uvp, vvp)					\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
# endif
# ifndef timercmp
#  define timercmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
# endif
# define timereq(tvp, uvp)						\
	((tvp)->tv_sec == (uvp)->tv_sec &&				\
	 (tvp)->tv_usec == (uvp)->tv_usec)

struct ArgusDhcpIntvlNode;

RB_HEAD(dhcp_intvl_tree, ArgusDhcpIntvlNode);

struct ArgusDhcpIntvlNode {
   RB_ENTRY(ArgusDhcpIntvlNode) inttree;
   struct timeval intlo, inthi;     /* interval low/start and hi/end times */
   struct timeval subtreehi;
   struct ArgusDhcpStruct *data;
};

struct ArgusDhcpIntvlTree {
  struct dhcp_intvl_tree inttree;
  pthread_mutex_t lock;
};

typedef int (*IntvlTreeCallback)(void *, struct ArgusDhcpIntvlNode *);

struct invecStruct {
   size_t nitems;
   size_t used;
   struct ArgusDhcpIntvlNode *invec;
};

struct ArgusDhcpIntvlTree *ArgusDhcpIntvlTreeAlloc(void);
void ArgusDhcpIntvlTreeFree(struct ArgusDhcpIntvlTree *);
int ArgusDhcpIntvlTreeEmpty(const struct ArgusDhcpIntvlTree * const);
int ArgusDhcpIntvlTreeInsert(struct ArgusDhcpIntvlTree *,
                             const struct timeval * const,
                             uint32_t,
                             struct ArgusDhcpStruct *);
int ArgusDhcpIntvlTreeRemove(struct ArgusDhcpIntvlTree *,
                             const struct timeval * const intlo);
struct ArgusDhcpIntvlNode *IntvlTreeFind(struct ArgusDhcpIntvlTree *head,
                                         const struct timeval * const intlo);
struct ArgusDhcpIntvlNode *IntvlTreeFindByStruct(struct ArgusDhcpIntvlTree *,
                                                 struct ArgusDhcpStruct *);
int IntvlTreeForEach(struct ArgusDhcpIntvlTree * const,
                      IntvlTreeCallback cb, void *);
int IntvlTreeForEachOverlaps(struct ArgusDhcpIntvlTree * const,
                             IntvlTreeCallback, void *,
                             const struct timeval * const,
                             const struct timeval * const);
int IntvlTreeDump(struct ArgusDhcpIntvlTree *);
ssize_t IntvlTreeOverlapsRange(struct ArgusDhcpIntvlTree *in,
                               const struct timeval * const start,
                               const struct timeval * const stop,
                               struct ArgusDhcpIntvlNode *invec,
                               size_t nitems);

#endif
