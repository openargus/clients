/*
**
** $Id: acsmx.c,v 1.1 2003/10/20 15:03:42 chrisgreen Exp $
**
** Multi-Pattern Search Engine
**
** Aho-Corasick State Machine -  uses a Deterministic Finite Automata - DFA
**
** Copyright (C) 2002 Sourcefire,Inc.
** Marc Norton
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
**
**   Reference - Efficient String matching: An Aid to Bibliographic Search
**               Alfred V Aho and Margaret J Corasick
**               Bell Labratories 
**               Copyright(C) 1975 Association for Computing Machinery,Inc
**
**   Implemented from the 4 algorithms in the paper by Aho & Corasick
**   and some implementation ideas from 'Practical Algorithms in C'
**
**   Notes:
**     1) This version uses about 1024 bytes per pattern character - heavy  on the memory. 
**     2) This algorithm finds all occurrences of all patterns within a  
**        body of text.
**     3) Support is included to handle upper and lower case matching.     
**     4) Some comopilers optimize the search routine well, others don't, this makes all the difference.
**     5) Aho inspects all bytes of the search text, but only once so it's very efficient,
**        if the patterns are all large than the Modified Wu-Manbar method is often faster.
**     6) I don't subscribe to any one method is best for all searching needs,
**        the data decides which method is best,
**        and we don't know until after the search method has been tested on the specific data sets.
**        
**
**  May 2002  : Marc Norton 1st Version  
**  June 2002 : Modified interface for SNORT, added case support
**  Aug 2002  : Cleaned up comments, and removed dead code.
**  Nov 2,2002: Fixed queue_init() , added count=0
**              
** 
*/  
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
  
#include "acsmx.h"
  
#define MEMASSERT(p,s) if(!p){fprintf(stderr,"ACSM-No Memory: %s!\n",s);exit(0);}

#ifdef DEBUG_AC
static int max_memory = 0;
#endif

/*
*
*/ 
static void *
AC_MALLOC (int n) 
{
  void *p;
  p = malloc (n);
#ifdef DEBUG_AC
  if (p)
    max_memory += n;
#endif
  return p;
}


/*
*
*/ 
static void
AC_FREE (void *p) 
{
  if (p)
    free (p);
}


/*
*    Simple QUEUE NODE
*/ 
typedef struct _qnode
{
  int state;
   struct _qnode *next;
}
QNODE;

/*
*    Simple QUEUE Structure
*/ 
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
}
QUEUE;

/*
*
*/ 
static void
queue_init (QUEUE * s) 
{
  s->head = s->tail = 0;
  s->count = 0;
}


/*
*  Add Tail Item to queue
*/ 
static void
queue_add (QUEUE * s, int state) 
{
  QNODE * q;
  if (!s->head)
    {
      q = s->tail = s->head = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->state = state;
      q->next = 0;
    }
  else
    {
      q = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->state = state;
      q->next = 0;
      s->tail->next = q;
      s->tail = q;
    }
  s->count++;
}


/*
*  Remove Head Item from queue
*/ 
static int
queue_remove (QUEUE * s) 
{
  int state = 0;
  QNODE * q;
  if (s->head)
    {
      q = s->head;
      state = q->state;
      s->head = s->head->next;
      s->count--;
      if (!s->head)
	{
	  s->tail = 0;
	  s->count = 0;
	}
      AC_FREE (q);
    }
  return state;
}


/*
*
*/ 
static int
queue_count (QUEUE * s) 
{
  return s->count;
}


/*
*
*/ 
static void
queue_free (QUEUE * s) 
{
  while (queue_count (s))
    {
      queue_remove (s);
    }
}


/*
** Case Translation Table 
*/ 
static unsigned char xlatcase[256];

/*
*
*/ 
  static void
init_xlatcase () 
{
  int i;
  for (i = 0; i < 256; i++)
    {
      xlatcase[i] = toupper (i);
    }
}


/*
*
*/ 
  static inline void
ConvertCase (unsigned char *s, int m) 
{
  int i;
  for (i = 0; i < m; i++)
    {
      s[i] = xlatcase[s[i]];
    }
}


/*
*
*/ 
static inline void
ConvertCaseEx (unsigned char *d, unsigned char *s, int m) 
{
  int i;
  for (i = 0; i < m; i++)
    {
      d[i] = xlatcase[s[i]];
    }
}


/*
*
*/ 
static ACSM_PATTERN *
CopyMatchListEntry (ACSM_PATTERN * px) 
{
  ACSM_PATTERN * p;
  p = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (p, "CopyMatchListEntry");
  memcpy (p, px, sizeof (ACSM_PATTERN));
  p->next = 0;
  return p;
}


/*
*  Add a pattern to the list of patterns terminated at this state.
*  Insert at front of list.
*/ 
static void
AddMatchListEntry (ACSM_STRUCT * acsm, int state, ACSM_PATTERN * px) 
{
  ACSM_PATTERN * p;
  p = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (p, "AddMatchListEntry");
  memcpy (p, px, sizeof (ACSM_PATTERN));
  p->next = acsm->acsmStateTable[state].MatchList;
  acsm->acsmStateTable[state].MatchList = p;
}


/* 
   Add Pattern States
*/ 
static void
AddPatternStates (ACSM_STRUCT * acsm, ACSM_PATTERN * p) 
{
  unsigned char *pattern;
  int state=0, next, n;
  n = p->n;
  pattern = p->patrn;
  
    /* 
     *  Match up pattern with existing states
     */ 
    for (; n > 0; pattern++, n--)
    {
      next = acsm->acsmStateTable[state].NextState[*pattern];
      if (next == ACSM_FAIL_STATE)
	break;
      state = next;
    }
  
    /*
     *   Add new states for the rest of the pattern bytes, 1 state per byte
     */ 
    for (; n > 0; pattern++, n--)
    {
      acsm->acsmNumStates++;
      acsm->acsmStateTable[state].NextState[*pattern] = acsm->acsmNumStates;
      state = acsm->acsmNumStates;
    }
    
  AddMatchListEntry (acsm, state, p);
}


/*
*   Build Non-Deterministic Finite Automata
*/ 
static void
Build_NFA (ACSM_STRUCT * acsm) 
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;
  ACSM_PATTERN * mlist=0;
  ACSM_PATTERN * px=0;
  
    /* Init a Queue */ 
    queue_init (queue);
  
    /* Add the state 0 transitions 1st */ 
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
      s = acsm->acsmStateTable[0].NextState[i];
      if (s)
	{
	  queue_add (queue, s);
	  acsm->acsmStateTable[s].FailState = 0;
	}
    }
  
    /* Build the fail state transitions for each valid state */ 
    while (queue_count (queue) > 0)
    {
      r = queue_remove (queue);
      
	/* Find Final States for any Failure */ 
	for (i = 0; i < ALPHABET_SIZE; i++)
	{
	  int fs, next;
	  if ((s = acsm->acsmStateTable[r].NextState[i]) != ACSM_FAIL_STATE)
	    {
	      queue_add (queue, s);
	      fs = acsm->acsmStateTable[r].FailState;
	      
		/* 
		   *  Locate the next valid state for 'i' starting at s 
		 */ 
		while ((next=acsm->acsmStateTable[fs].NextState[i]) ==
		       ACSM_FAIL_STATE)
		{
		  fs = acsm->acsmStateTable[fs].FailState;
		}
	      
		/*
		   *  Update 's' state failure state to point to the next valid state
		 */ 
		acsm->acsmStateTable[s].FailState = next;
	      
		/*
		   *  Copy 'next'states MatchList to 's' states MatchList, 
		   *  we copy them so each list can be AC_FREE'd later,
		   *  else we could just manipulate pointers to fake the copy.
		 */ 
		for (mlist  = acsm->acsmStateTable[next].MatchList; 
		     mlist != NULL ;
		     mlist  = mlist->next)
		{
		    px = CopyMatchListEntry (mlist);

		    if( !px )
		    {
		    printf("*** Out of memory Initializing Aho Corasick in acsmx.c ****");
		    }
	
		    /* Insert at front of MatchList */ 
		    px->next = acsm->acsmStateTable[s].MatchList;
		    acsm->acsmStateTable[s].MatchList = px;
		}
	    }
	}
    }
  
    /* Clean up the queue */ 
    queue_free (queue);
}


/*
*   Build Deterministic Finite Automata from NFA
*/ 
static void
Convert_NFA_To_DFA (ACSM_STRUCT * acsm) 
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;
  
    /* Init a Queue */ 
    queue_init (queue);
  
    /* Add the state 0 transitions 1st */ 
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
      s = acsm->acsmStateTable[0].NextState[i];
      if (s)
	{
	  queue_add (queue, s);
	}
    }
  
    /* Start building the next layer of transitions */ 
    while (queue_count (queue) > 0)
    {
      r = queue_remove (queue);
      
	/* State is a branch state */ 
	for (i = 0; i < ALPHABET_SIZE; i++)
	{
	  if ((s = acsm->acsmStateTable[r].NextState[i]) != ACSM_FAIL_STATE)
	    {
	      queue_add (queue, s);
	    }
	  else
	    {
	      acsm->acsmStateTable[r].NextState[i] =
		acsm->acsmStateTable[acsm->acsmStateTable[r].FailState].
		NextState[i];
	    }
	}
    }
  
    /* Clean up the queue */ 
    queue_free (queue);
}


/*
*
*/ 
ACSM_STRUCT * acsmNew () 
{
  ACSM_STRUCT * p;
  init_xlatcase ();
  p = (ACSM_STRUCT *) AC_MALLOC (sizeof (ACSM_STRUCT));
  MEMASSERT (p, "acsmNew");
  if (p)
    memset (p, 0, sizeof (ACSM_STRUCT));
  return p;
}


/*
*   Add a pattern to the list of patterns for this state machine
*/ 
int
acsmAddPattern (ACSM_STRUCT * p, unsigned char *pat, int n, int nocase,
		int offset, int depth, void * id, int iid) 
{
  ACSM_PATTERN * plist;
  plist = (ACSM_PATTERN *) AC_MALLOC (sizeof (ACSM_PATTERN));
  MEMASSERT (plist, "acsmAddPattern");
  plist->patrn = (unsigned char *) AC_MALLOC (n);
  ConvertCaseEx (plist->patrn, pat, n);
  plist->casepatrn = (unsigned char *) AC_MALLOC (n);
  memcpy (plist->casepatrn, pat, n);
  plist->n = n;
  plist->nocase = nocase;
  plist->offset = offset;
  plist->depth = depth;
  plist->id = id;
  plist->iid = iid;
  plist->next = p->acsmPatterns;
  p->acsmPatterns = plist;
  return 0;
}


/*
*   Compile State Machine
*/ 
int
acsmCompile (ACSM_STRUCT * acsm) 
{
  int i, k;
  ACSM_PATTERN * plist;
  
    /* Count number of states */ 
    acsm->acsmMaxStates = 1;
  for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
      acsm->acsmMaxStates += plist->n;
    }
  acsm->acsmStateTable =
    (ACSM_STATETABLE *) AC_MALLOC (sizeof (ACSM_STATETABLE) *
				   acsm->acsmMaxStates);
  MEMASSERT (acsm->acsmStateTable, "acsmCompile");
  memset (acsm->acsmStateTable, 0,
	    sizeof (ACSM_STATETABLE) * acsm->acsmMaxStates);
  
    /* Initialize state zero as a branch */ 
    acsm->acsmNumStates = 0;
  
    /* Initialize all States NextStates to FAILED */ 
    for (k = 0; k < acsm->acsmMaxStates; k++)
    {
      for (i = 0; i < ALPHABET_SIZE; i++)
	{
	  acsm->acsmStateTable[k].NextState[i] = ACSM_FAIL_STATE;
	}
    }
  
    /* Add each Pattern to the State Table */ 
    for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
      AddPatternStates (acsm, plist);
    }
  
    /* Set all failed state transitions to return to the 0'th state */ 
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
      if (acsm->acsmStateTable[0].NextState[i] == ACSM_FAIL_STATE)
	{
	  acsm->acsmStateTable[0].NextState[i] = 0;
	}
    }
  
    /* Build the NFA  */ 
    Build_NFA (acsm);
  
    /* Convert the NFA to a DFA */ 
    Convert_NFA_To_DFA (acsm);
  
    /*printf ("ACSMX-Max Memory: %d bytes, %d states\n", max_memory,
	     acsm->acsmMaxStates);
	     */
  return 0;
}


static unsigned char Tc[64*1024];

/*
*   Search Text or Binary Data for Pattern matches
*/ 
  int
acsmSearch (ACSM_STRUCT * acsm, unsigned char *Tx, int n,
	    int (*Match) (void *  id, int index, void *data), void *data) 
{
  int state;
  ACSM_PATTERN * mlist;
  unsigned char *Tend;
  ACSM_STATETABLE * StateTable = acsm->acsmStateTable;
  int nfound = 0;
  unsigned char *T;
  int index;
  
  /* Case conversion */ 
  ConvertCaseEx (Tc, Tx, n);
  T = Tc;
  Tend = T + n;
 
  for (state = 0; T < Tend; T++)
    {
      state = StateTable[state].NextState[*T];

      if( StateTable[state].MatchList != NULL )
	{
	  for( mlist=StateTable[state].MatchList; mlist!=NULL;
	       mlist=mlist->next )
	    {
	      index = T - mlist->n + 1 - Tc;
	      if( mlist->nocase )
		{
		  nfound++;
		  if (Match (mlist->id, index, data))
		    return nfound;
		}
	      else
		{
		  if( memcmp (mlist->casepatrn, Tx + index, mlist->n) == 0 )
		    {
		      nfound++;
		      if (Match (mlist->id, index, data))
			return nfound;
		    }
		}
	    }
	}
    }
  return nfound;
}


/*
*   Free all memory
*/ 
  void
acsmFree (ACSM_STRUCT * acsm) 
{
  int i;
  ACSM_PATTERN * mlist, *ilist;
  for (i = 0; i < acsm->acsmMaxStates; i++)
    
    {
      if (acsm->acsmStateTable[i].MatchList != NULL)
	
	{
	  mlist = acsm->acsmStateTable[i].MatchList;
	  while (mlist)
	    
	    {
	      ilist = mlist;
	      mlist = mlist->next;
	      AC_FREE (ilist);
	    }
	}
    }
  AC_FREE (acsm->acsmStateTable);
}


#ifdef ACSMX_MAIN
  
/*
*  Text Data Buffer
*/ 
unsigned char text[512];

/* 
*    A Match is found
*/ 
  int
MatchFound (unsigned id, int index, void *data) 
{
  fprintf (stdout, "%s\n", (char *) id);
  return 0;
}


/*
*
*/ 
  int
main (int argc, char **argv) 
{
  int i, nocase = 0;
  ACSM_STRUCT * acsm;
  if (argc < 3)
    
    {
      fprintf (stderr,
		"Usage: acsmx pattern word-1 word-2 ... word-n  -nocase\n");
      exit (0);
    }
  acsm = acsmNew ();
  strcpy (text, argv[1]);
  for (i = 1; i < argc; i++)
    if (strcmp (argv[i], "-nocase") == 0)
      nocase = 1;
  for (i = 2; i < argc; i++)
    
    {
      if (argv[i][0] == '-')
	continue;
      acsmAddPattern (acsm, argv[i], strlen (argv[i]), nocase, 0, 0,
			argv[i], i - 2);
    }
  acsmCompile (acsm);
  acsmSearch (acsm, text, strlen (text), MatchFound, (void *) 0);
  acsmFree (acsm);
  printf ("normal pgm end\n");
  return (0);
}
#endif /*  */

