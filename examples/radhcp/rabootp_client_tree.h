#ifndef __RABOOTP_CLIENT_TREE_H
# define __RABOOTP_CLIENT_TREE_H
# include "argus_config.h"
# include "bsd/sys/tree.h"
# include "rabootp.h"

struct ArgusDhcpClientNode;

RB_HEAD(dhcp_client_tree, ArgusDhcpClientNode);

struct ArgusDhcpClientNode {
   RB_ENTRY(ArgusDhcpClientNode) tree;
   struct ArgusDhcpStruct *data;
};

struct ArgusDhcpClientTree {
  struct dhcp_client_tree tree;
  pthread_mutex_t lock;
};

typedef int (*ClientTreeCallback)(void *, struct ArgusDhcpClientNode *);

struct ArgusDhcpClientTree *ArgusDhcpClientTreeAlloc(void);
void ArgusDhcpClientTreeFree(struct ArgusDhcpClientTree *);
int ArgusDhcpClientTreeInsert(struct ArgusDhcpClientTree *,
                              struct ArgusDhcpStruct *);
int ArgusDhcpClientTreeRemove(struct ArgusDhcpClientTree *,
                              struct ArgusDhcpStruct *);
struct ArgusDhcpStruct *ClientTreeFind(struct ArgusDhcpClientTree *head,
                                       const unsigned char * const chaddr,
                                       unsigned char hlen, unsigned xid);
struct ArgusDhcpStruct *ClientTreeFindByStruct(struct ArgusDhcpClientTree *,
                                               struct ArgusDhcpStruct *);
int ClientTreeForEach(struct ArgusDhcpClientTree * const,
                      ClientTreeCallback cb, void *);
#endif
