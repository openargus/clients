/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2001 Phil Wood <cpw@lanl.gov>
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

/* $Id: sp_ip_same_check.c,v 1.10 2003/10/20 15:03:30 chrisgreen Exp $ */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"



typedef struct _IpSameData
{
    u_char ip_same;

} IpSameData;

void IpSameCheckInit(char *, OptTreeNode *, int);
void ParseIpSame(char *, OptTreeNode *);
int IpSameCheck(Packet *, struct _OptTreeNode *, OptFpList *);


/****************************************************************************
 * 
 * Function: SetupIpSameCheck()
 *
 * Purpose: Associate the same keyword with IpSameCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpSameCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("sameip", IpSameCheckInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: IpSameCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: IpSameCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Setup the same data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpSameCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_IP_SAME_CHECK])
    {
        FatalError("%s(%d): Multiple sameip options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_IP_SAME_CHECK] = (IpSameData *)
            SnortAlloc(sizeof(IpSameData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIpSame(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(IpSameCheck, otn);
}



/****************************************************************************
 * 
 * Function: ParseIpSame(char *, OptTreeNode *)
 *
 * Purpose: Convert the id option argument to data and plug it into the 
 *          data structure
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIpSame(char *data, OptTreeNode *otn)
{
    IpSameData *ds_ptr;  /* data struct pointer */

    return; /* the check below bombs. */
    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_IP_SAME_CHECK];

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }
    if (*data) {
        FatalError("%s(%d): arg '%s' not required\n", file_name, file_line, data);
    }
}


/****************************************************************************
 * 
 * Function: IpSameCheck(char *, OptTreeNode *)
 *
 * Purpose: Test the ip header's id field to see if its value is equal to the
 *          value in the rule.  This is useful to detect things like "elite"
 *          numbers, oddly repeating numbers, etc.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int IpSameCheck(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->iph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
               */
    if (p->iph->ip_src.s_addr == p->iph->ip_dst.s_addr) 
    {

	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Match!  %x -> %x\n",
				p->iph->ip_src.s_addr,  p->iph->ip_dst.s_addr););
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match %x -> %x\n",
				p->iph->ip_src.s_addr,  p->iph->ip_dst.s_addr););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}
