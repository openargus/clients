#ifndef __RABOOTP_MEMORY_H
# define __RABOOTP_MEMORY_H
# include "rabootp.h"

struct ArgusDhcpStruct *ArgusDhcpStructAlloc(void);
void ArgusDhcpStructFreeReplies(void *);
void ArgusDhcpStructFreeRequest(void *);
void ArgusDhcpStructFree(void *);
void ArgusDhcpStructUpRef(struct ArgusDhcpStruct *);

#endif
