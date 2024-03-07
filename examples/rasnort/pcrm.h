/*
** $Id: pcrm.h,v 1.1 2004/05/12 00:04:26 qosient Exp $
**
** pcrm.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Marc Norton <mnorton@sourcefire.com>
** Dan Roelker <droelker@sourcefire.com>
**
** 
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
**
** Packet Classification-Rule Manager
**
*/
#ifndef _PCRM_H
#define _PCRM_H

#include "sfutil/bitop.h"

typedef void * RULE_PTR;

#define MAX_PORTS 64*1024
#define ANYPORT   -1


/*
** Macros to walk a RULE_NODE list, and get the
** RULE_PTR from a RULE_NODE, these eliminate 
** subroutine calls, in high performance needs.
*/
#define PRM_GET_FIRST_GROUP_NODE(pg) (pg->pgHead)
#define PRM_GET_NEXT_GROUP_NODE(rn)  (rn->rnNext)

#define PRM_GETRULE_FROM_NODE(rn)     (rn->rnRuleData)

#define PRM_GET_FIRST_GROUP_NODE_NC(pg) (pg->pgHeadNC)
#define PRM_GET_NEXT_GROUP_NODE_NC(rn)  (rn->rnNext)

typedef struct _not_rule_node_ {

  struct _not_rule_node_ * next;
  
  int iPos; /* RULE_NODE->iRuleNodeID */
  
  
} NOT_RULE_NODE;


typedef struct _rule_node_ {

  struct  _rule_node_ * rnNext;
 
  RULE_PTR rnRuleData; 

  int iRuleNodeID;
 
}RULE_NODE;


typedef struct {
  
  /* Content List */
  RULE_NODE *pgHead, *pgTail, *pgCur;
  int   pgContentCount;
 
  /* No-Content List */
  RULE_NODE *pgHeadNC, *pgTailNC, *pgCurNC;
  int   pgNoContentCount;

  /*  Uri-Content List */
  RULE_NODE *pgUriHead, *pgUriTail, *pgUriCur;
  int   pgUriContentCount;
 
  /* Setwise Pattern Matching data structures */
  void * pgPatData;
  void * pgPatDataUri;
  
  int avgLen;  
  int minLen;
  int maxLen;
  int c1,c2,c3,c4,c5;

  /*
  **  Bit operation for validating matches
  */
  BITOP boRuleNodeID;
  
  /*
  *   Not rule list for this group
  */
  NOT_RULE_NODE *pgNotRuleList;

  /*
  **  Count of rule_node's in this group/list 
  */
  int pgCount;

  int pgNQEvents;
  int pgQEvents;
 
}PORT_GROUP;



typedef struct {

  int        prmNumDstRules;
  int        prmNumSrcRules;
  int        prmNumGenericRules;
  
  int        prmNumDstGroups;
  int        prmNumSrcGroups;

  PORT_GROUP *prmSrcPort[MAX_PORTS];
  PORT_GROUP *prmDstPort[MAX_PORTS];
  /* char       prmConflicts[MAX_PORTS]; */
  PORT_GROUP *prmGeneric;

} PORT_RULE_MAP ;


typedef struct {

  int        prmNumRules;
  int        prmNumGenericRules;
  
  int        prmNumGroups;

  PORT_GROUP prmByteGroup[256];
  PORT_GROUP prmGeneric;

} BYTE_RULE_MAP ;


PORT_RULE_MAP * prmNewMap( );
BYTE_RULE_MAP * prmNewByteMap( );

void prmFreeMap( PORT_RULE_MAP * p );
void prmFreeByteMap( BYTE_RULE_MAP * p );

int prmAddRule( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd );
int prmAddByteRule( BYTE_RULE_MAP * p, int dport, RULE_PTR rd );

int prmAddRuleUri( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd );
int prmAddRuleNC( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd );
int prmAddByteRuleNC( BYTE_RULE_MAP * p, int dport, RULE_PTR rd );

void prmAddNotNode( PORT_GROUP * pg, int id );

int prmCompileGroups( PORT_RULE_MAP * p );
int prmCompileByteGroups( BYTE_RULE_MAP * p );

int prmShowStats( PORT_RULE_MAP * p );
int prmShowByteStats( BYTE_RULE_MAP * p );

int prmShowEventStats( PORT_RULE_MAP * p );
int prmShowEventByteStats( BYTE_RULE_MAP * p );

RULE_PTR prmGetFirstRule( PORT_GROUP * pg );
RULE_PTR prmGetNextRule( PORT_GROUP * pg );

RULE_PTR prmGetFirstRuleUri( PORT_GROUP * pg );
RULE_PTR prmGetNextRuleUri( PORT_GROUP * pg );

RULE_PTR prmGetFirstRuleNC( PORT_GROUP * pg );
RULE_PTR prmGetNextRuleNC( PORT_GROUP * pg );


int prmFindRuleGroup( PORT_RULE_MAP * p, int dport, int sport, PORT_GROUP ** src, PORT_GROUP **dst , PORT_GROUP ** gen);
int prmFindByteRuleGroup( BYTE_RULE_MAP * p, int dport, PORT_GROUP **dst , PORT_GROUP ** gen);

PORT_GROUP * prmFindDstRuleGroup( PORT_RULE_MAP * p, int port );
PORT_GROUP * prmFindSrcRuleGroup( PORT_RULE_MAP * p, int port );

PORT_GROUP * prmFindByteRuleGroupUnique( BYTE_RULE_MAP * p, int port );

int      prmSetGroupPatData( PORT_GROUP * pg, void * data );
void *   prmGetGroupPatData( PORT_GROUP * pg );


#endif
