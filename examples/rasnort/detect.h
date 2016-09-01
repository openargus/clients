/* $Id: detect.h,v 1.2 2004/05/14 15:44:35 qosient Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/*  I N C L U D E S  ************************************************/
#ifndef __DETECT_H__
#define __DETECT_H__

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

//#include "snort.h"

#include "argus_client.h"
#include "decode.h"
#include "rules.h"
#include "parser.h"
#include "log.h"
#include "event.h"
/*  P R O T O T Y P E S  ******************************************************/
extern int do_detect;

/* rule match action functions */
int PassAction();
int ActivateAction(struct ArgusRecord *, OptTreeNode *, Event *);
int AlertAction(struct ArgusRecord *, OptTreeNode *, Event *);
int DynamicAction(struct ArgusRecord *, OptTreeNode *, Event *);
int LogAction(struct ArgusRecord *, OptTreeNode *, Event *);

/* detection/manipulation funcs */
int Preprocess(struct ArgusRecord *);
int Detect(struct ArgusRecord *);
void CallOutputPlugins(struct ArgusRecord *);
int EvalArgusRecord(ListHead *, int, struct ArgusRecord * );
int EvalHeader(RuleTreeNode *, struct ArgusRecord *, int);
int EvalOpts(OptTreeNode *, struct ArgusRecord *);
void TriggerResponses(struct ArgusRecord *, OptTreeNode *);
int CheckAddrPort(IpAddrSet *, u_short, u_short, struct ArgusRecord *, u_int32_t, int);

static inline void DisableDetect(struct ArgusRecord *p) {
    do_detect = 0;
}

/* detection modules */
int CheckBidirectional(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIP(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIP(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIPNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIPNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortEqual(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortEqual(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);

int RuleListEnd(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *);
int OptListEnd(struct ArgusRecord *, struct _OptTreeNode *, OptFpList *);
void CallLogPlugins(struct ArgusRecord *, char *, void *, Event *);
void CallAlertPlugins(struct ArgusRecord *, char *, void *, Event *);
void CallLogFuncs(struct ArgusRecord *, char *, ListHead *, Event *);
void CallAlertFuncs(struct ArgusRecord *, char *, ListHead *, Event *);

void ObfuscatePacket(Packet *p);

#endif /* __DETECT_H__ */
