/*
** $Id: sp_flowbits.c,v 1.1.2.2 2004/03/31 18:28:16 jh8 Exp $
**
** sp_flowbits
** 
** Purpose:
**
** Wouldn't it be nice if we could do some simple state tracking 
** across multiple packets?  Well, this allows you to do just that.
**
** Effect:
**
** - [Un]set a bitmask stored with the session
** - Check the value of the bitmask
**
** Copyright (C) 2003 Sourcefire, Inc
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "snort.h"
#include "flow.h"
#include "bitop.h"
#include "sfghash.h"
#include "flow/flow.h"
#include "spp_flow.h"

/**
**  The FLOWBITS_OBJECT is used to track the different
**  flowbit names that set/unset/etc. bits.  We use these
**  so that we can verify that the rules that use flowbits
**  make sense.
**
**  The types element tracks all the different operations that
**  may occur for a given object.  This is different from how
**  the type element is used from the FLOWBITS_ITEM structure.
*/
typedef struct _FLOWBITS_OBJECT
{
    u_int32_t id;
    u_int8_t  types;
} FLOWBITS_OBJECT;

/**
**  This structure is the context ptr for each detection option
**  on a rule.  The id is associated with a FLOWBITS_OBJECT id.
**
**  The type element track only one operation.
*/
typedef struct _FLOWBITS_OP
{
    u_int32_t id;
    u_int8_t  type;        /* Set, Unset, Invert, IsSet, IsNotSet, Reset  */
} FLOWBITS_OP;

#define FLOWBITS_SET       0x01  
#define FLOWBITS_UNSET     0x02
#define FLOWBITS_TOGGLE    0x04
#define FLOWBITS_ISSET     0x08
#define FLOWBITS_ISNOTSET  0x10
#define FLOWBITS_RESET     0x20
#define FLOWBITS_NOALERT   0x40

extern unsigned int giFlowbitSize;

static u_int32_t flowbits_count = 0;
static SFGHASH *flowbits_hash;

static void FlowBitsInit(char *, OptTreeNode *, int);
static void FlowBitsParse(char *, FLOWBITS_OP *, OptTreeNode *);
static int  FlowBitsCheck(Packet *, struct _OptTreeNode *, OptFpList *);

/****************************************************************************
 * 
 * Function: SetupFlowBits()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupFlowBits()
{
    /* setup our storage hash */
    flowbits_hash = sfghash_new( 100, 0 , 0, 0);
    if (!flowbits_hash) {
        FatalError("Could not setup flowbits hash\n");
    }

    /* map the keyword to an initialization/processing function */
    RegisterPlugin("flowbits", FlowBitsInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: FlowBits Setup\n"););
}


/****************************************************************************
 * 
 * Function: FlowBitsInit(char *, OptTreeNode *)
 *
 * Purpose: Configure the flow init option to register the appropriate checks
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
static void FlowBitsInit(char *data, OptTreeNode *otn, int protocol)
{
    FLOWBITS_OP *flowbits;
    OptFpList *fpl;
 
    if(!SppFlowIsRunning())
    {
        LogMessage("Warning: %s (%d) => flowbits without flow.  flow must be enabled for this plugin.\n", file_name,file_line);
    }

    flowbits = (FLOWBITS_OP *) SnortAlloc(sizeof(FLOWBITS_OP));
    if (!flowbits) {
        FatalError("%s (%d): Unable to allocate flowbits node\n", file_name,
                file_line);
    }

    FlowBitsParse(data, flowbits, otn);
    fpl = AddOptFuncToList(FlowBitsCheck, otn);

    /*
     * attach it to the context node so that we can call each instance 
     * individually
     */
    
    fpl->context = (void *) flowbits;
    return;
}


/****************************************************************************
 * 
 * Function: FlowBitsParse(char *, FlowBits *flowbits, OptTreeNode *)
 *
 * Purpose: parse the arguments to the flow plugin and alter the otn
 *          accordingly
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
static void FlowBitsParse(char *data, FLOWBITS_OP *flowbits, OptTreeNode *otn)
{
    FLOWBITS_OBJECT *flowbits_item;
    char *token, *str, *p;
    u_int32_t id = 0;
    int hstatus;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "flowbits parsing %s\n",data););
    
    str = strdup(data);

    if(str == NULL)
    {
        FatalError("ParseFlowArgs: Can't strdup data\n");
    }

    p = str;

    /* nuke leading whitespace */
    while(isspace((int)*p)) p++;

    token = strtok(p, ",");
    if(!token)
    {
        FatalError("%s(%d) ParseFlowArgs: Must specify flowbits operation.",
                file_name, file_line);
    }

    while(isspace((int)*token))
        token++;

    if(!strncasecmp("set",token,3))
    {
        flowbits->type = FLOWBITS_SET;
    } 
    else if(!strncasecmp("unset",token,5))
    {
        flowbits->type = FLOWBITS_UNSET;
    }
    else if(!strncasecmp("toggle",token,6))
    {
        flowbits->type = FLOWBITS_TOGGLE;
    }
    else if(!strncasecmp("isset",token,5))
    {
        flowbits->type = FLOWBITS_ISSET;
    }
    else if(!strncasecmp("isnotset",token,8))
    {
        flowbits->type = FLOWBITS_ISNOTSET;
    } 
    else if(!strncasecmp("noalert", token, 7))
    {
        if(strtok(NULL, " ,\t"))
        {
            FatalError("%s (%d): Do not specify a flowbits tag id for the "
                       "keyword 'noalert'.\n", file_name, file_line);
        }

        flowbits->type = FLOWBITS_NOALERT;
        flowbits->id   = 0;
        free(str);
        return;
    }
    else if(!strncasecmp("reset",token,5))
    {
        if(strtok(NULL, " ,\t"))
        {
            FatalError("%s (%d): Do not specify a flowbits tag id for the "
                       "keyword 'reset'.\n", file_name, file_line);
        }

        flowbits->type = FLOWBITS_RESET;
        flowbits->id   = 0;
        free(str);
        return;
    } 
    else
    {
        FatalError("%s(%d) ParseFlowArgs: Invalid token %s\n",
                file_name, file_line, token);
    }

    /*
    **  Let's parse the flowbits name
    */
    token = strtok(NULL, " ,\t");
    if(!token || !strlen(token))
    {
        FatalError("%s (%d): flowbits tag id must be provided\n",
                file_name, file_line);
    }

    /*
    **  Take space from the beginning
    */
    while(isspace((int)*token)) 
        token++;

    /*
    **  Do we still have a ID tag left.
    */
    if (!strlen(token))
    {
        FatalError("%s (%d): flowbits tag id must be provided\n",
                file_name, file_line);
    }

    /*
    **  Is there a anything left?
    */
    if(strtok(NULL, " ,\t"))
    {
        FatalError("%s (%d): flowbits tag id cannot include spaces or "
                   "commas.\n", file_name, file_line);
    }
    
    flowbits_item = (FLOWBITS_OBJECT *)sfghash_find(flowbits_hash, token);

    if (flowbits_item) 
    {
        flowbits_item->types |= flowbits->type;
        id = flowbits_item->id;
    } 
    else
    {
        flowbits_item = 
            (FLOWBITS_OBJECT *)SnortAlloc(sizeof(FLOWBITS_OBJECT));

        flowbits_item->id = flowbits_count;
        flowbits_item->types |= flowbits->type;

        hstatus = sfghash_add( flowbits_hash, token, flowbits_item);
        if(hstatus) 
        {
            FatalError("Could not add flowbits key (%s) to hash",token);
        }

        id = flowbits_count;
        flowbits_count++;

        if(flowbits_count >= giFlowbitSize)
        {
            FatalError("FLOWBITS ERROR: The number of flowbit IDs in the "
                       "current ruleset exceed the maximum number of IDs "
                       "that are allowed.\n");
        }
    }

    flowbits->id = id;

    free(str);
}

static int ResetFlowbits(Packet *p)
{
    Session *ssn;

    if(!p || !p->ssnptr)
    {
        return 0;
    }

    ssn = p->ssnptr;

    /*
    **  Check session_flags for new TCP session
    **
    **  PKT_STREAM_EST is pretty obvious why it's in here
    **
    **  SEEN_CLIENT and SEEN_SERVER allow us to only reset the bits
    **  once on the first SYN pkt.  There after bits will be
    **  accumulated for that session.
    */
    if((p->packet_flags & PKT_STREAM_EST) ||
       ((ssn->session_flags & (SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER)) == 
        (SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER)))
    {
        return 0;
    }

    return 1;
}

/*
**  NAME
**    GetFlowbitsData::
*/
/**
**  This function initializes/retrieves flowbits data that is associated
**  with a given flow.
*/
static FLOWDATA *GetFlowbitsData(Packet *p)
{
    FLOW     *fp;
    FLOWDATA *flowdata;

    if(!p->flow)
    {
        return NULL;
    }

    fp = (FLOW *)p->flow;

    flowdata = &(fp->data);
    if(!flowdata)
        return NULL;

    /*
    **  Since we didn't initialize BITOP (which resets during init)
    **  we have to check for resetting here, because it may be
    **  a new flow.
    **
    **  NOTE:
    **    We can only do this on TCP flows because we know when a
    **    connection begins and ends.  So that's what we check.
    */
    if(ResetFlowbits(p))
    {
        boResetBITOP(&(flowdata->boFlowbits));
    }

    return flowdata;
}

/****************************************************************************
 * 
 * Function: FlowBitsCheck(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check flow bits foo 
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
static int FlowBitsCheck(Packet *p,struct _OptTreeNode *otn, OptFpList *fp_list)
{
    FLOWBITS_OP *flowbits;   /* pointer to the eval struct */
    FLOWDATA *flowdata;
    int result = 0;

    if(!p)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                   "FLOWBITSCHECK: No pkt."););
        return 0;
    }

    flowdata = GetFlowbitsData(p);
    if(!flowdata)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No FLOWBITS_DATA"););
        return 0;
    }

    flowbits = (FLOWBITS_OP *) fp_list->context;

    DEBUG_WRAP
    (
        DebugMessage(DEBUG_PLUGIN,"flowbits: type = %d\n",flowbits->type);
        DebugMessage(DEBUG_PLUGIN,"flowbits: value = %d\n",flowbits->id);
    );

    switch(flowbits->type)
    {
        case FLOWBITS_SET:
            boSetBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_UNSET:
            boClearBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_RESET:
            boResetBITOP(&(flowdata->boFlowbits));
            result = 1;
            break;

        case FLOWBITS_ISSET:
            if(boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 1;
            }
            break;

        case FLOWBITS_ISNOTSET:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 0;
            }
            else
            {
                result = 1;
            }
            break;

        case FLOWBITS_TOGGLE:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                boClearBit(&(flowdata->boFlowbits),flowbits->id);
            }
            else
            {
                boSetBit(&(flowdata->boFlowbits),flowbits->id);
            }

            result = 1;

            break;

        case FLOWBITS_NOALERT:
            /*
            **  This logic allows us to put flowbits: noalert any where
            **  in the detection chain, and still do bit ops after this
            **  option.
            */
            fp_list->next->OptTestFunc(p, otn, fp_list->next);
            return 0;

        default:
            /*
            **  Always return failure here.
            */
            return 0;
    }
    
    /*
    **  Now return what we found
    */
    if (result == 1)
    {
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    return 0;
}

/****************************************************************************
 * 
 * Function: FlowBitsVerify()
 *
 * Purpose: Check flow bits foo to make sure its valid
 *
 * Arguments: 
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
void FlowBitsVerify(void)
{
    SFGHASH_NODE * n;
    FLOWBITS_OBJECT *fb;

    for (n = sfghash_findfirst(flowbits_hash); 
         n != 0; 
         n= sfghash_findnext(flowbits_hash))
    {
        fb = (FLOWBITS_OBJECT *)n->data;

        if (fb->types & FLOWBITS_SET) {
            if (!(fb->types & FLOWBITS_ISSET || fb->types & FLOWBITS_ISNOTSET))
            {
                LogMessage("Warning: flowbits key '%s' is set but not ever checked.\n",n->key);
            }
        } else {
            if (fb->types & FLOWBITS_ISSET || fb->types & FLOWBITS_ISNOTSET) {
                LogMessage("Warning: flowbits key '%s' is checked but not ever set.\n",n->key);
            }
        }
    }
}
