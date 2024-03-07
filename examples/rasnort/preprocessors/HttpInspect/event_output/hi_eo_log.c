/**
**  @file       hi_eo_log.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains the event output functionality that 
**              HttpInspect uses to log events and data associated with
**              the events.
**
**  Log events, retrieve events, and select events that HttpInspect
**  generates.
**  
**  Logging Events:
**    Since the object behind this is no memset()s, we have to rely on the
**    stack interface to make sure we don't log the same event twice.  So
**    if there are events in the stack we cycle through to make sure that
**    there are none available before we add a new event and increment the
**    stack count.  Then to reset the event queue, we just need to set the
**    stack count back to zero.
**
**  NOTES:
**    - Initial development.  DJR
*/
#include <stdlib.h>

#include "hi_si.h"
#include "hi_eo.h"
#include "hi_util_xmalloc.h"
#include "hi_return_codes.h"

/*
**  The client events and the priorities are listed here.
**  Any time that a new client event is added, we have to
**  add the event id and the priority here.  If you want to
**  change either of those characteristics, you have to change
**  them here. 
*/
static HI_EVENT_INFO client_event_info[HI_EO_CLIENT_EVENT_NUM] = {
    { HI_EO_CLIENT_ASCII, HI_EO_LOW_PRIORITY, HI_EO_CLIENT_ASCII_STR },
    { HI_EO_CLIENT_DOUBLE_DECODE, HI_EO_HIGH_PRIORITY,
        HI_EO_CLIENT_DOUBLE_DECODE_STR },
    { HI_EO_CLIENT_U_ENCODE, HI_EO_MED_PRIORITY, HI_EO_CLIENT_U_ENCODE_STR },
    { HI_EO_CLIENT_BARE_BYTE, HI_EO_HIGH_PRIORITY, HI_EO_CLIENT_BARE_BYTE_STR},
    { HI_EO_CLIENT_BASE36, HI_EO_HIGH_PRIORITY, HI_EO_CLIENT_BASE36_STR },
    { HI_EO_CLIENT_UTF_8, HI_EO_LOW_PRIORITY, HI_EO_CLIENT_UTF_8_STR },
    { HI_EO_CLIENT_IIS_UNICODE, HI_EO_LOW_PRIORITY, 
        HI_EO_CLIENT_IIS_UNICODE_STR },
    { HI_EO_CLIENT_MULTI_SLASH, HI_EO_MED_PRIORITY,
        HI_EO_CLIENT_MULTI_SLASH_STR },
    { HI_EO_CLIENT_IIS_BACKSLASH, HI_EO_MED_PRIORITY, 
        HI_EO_CLIENT_IIS_BACKSLASH_STR },
    { HI_EO_CLIENT_SELF_DIR_TRAV, HI_EO_HIGH_PRIORITY,
        HI_EO_CLIENT_SELF_DIR_TRAV_STR },
    { HI_EO_CLIENT_DIR_TRAV, HI_EO_LOW_PRIORITY, HI_EO_CLIENT_DIR_TRAV_STR },
    { HI_EO_CLIENT_APACHE_WS, HI_EO_MED_PRIORITY, HI_EO_CLIENT_APACHE_WS_STR },
    { HI_EO_CLIENT_IIS_DELIMITER, HI_EO_MED_PRIORITY,
        HI_EO_CLIENT_IIS_DELIMITER_STR },
    { HI_EO_CLIENT_NON_RFC_CHAR, HI_EO_HIGH_PRIORITY,
        HI_EO_CLIENT_NON_RFC_CHAR_STR },
    { HI_EO_CLIENT_OVERSIZE_DIR, HI_EO_HIGH_PRIORITY,
        HI_EO_CLIENT_OVERSIZE_DIR_STR },
    {HI_EO_CLIENT_LARGE_CHUNK, HI_EO_HIGH_PRIORITY,
        HI_EO_CLIENT_LARGE_CHUNK_STR },
    {HI_EO_CLIENT_PROXY_USE, HI_EO_LOW_PRIORITY,
        HI_EO_CLIENT_PROXY_USE_STR }
};

static HI_EVENT_INFO anom_server_event_info[HI_EO_ANOM_SERVER_EVENT_NUM] = {
    {HI_EO_ANOM_SERVER, HI_EO_HIGH_PRIORITY, HI_EO_ANOM_SERVER_STR }
};

/*
**  hi_eo_anom_server_event_log::
*/
/**
**  This routine logs anomalous server events to the event queue.
**  
**  @param Session   pointer to the HttpInspect session
**  @param iEvent    the event id for the client
**  @param data      pointer to the user data of the event
**  @param free_data pointer to a function to free the user data
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_INVALID_ARG invalid arguments
*/
int hi_eo_anom_server_event_log(HI_SESSION *Session, int iEvent, void *data,
        void (*free_data)(void *))
{
    HI_ANOM_SERVER_EVENTS *anom_server_events;
    HI_EVENT *event;
    int iCtr;

    /*
    **  Check the input variables for correctness
    */
    if(!Session || (iEvent >= HI_EO_ANOM_SERVER_EVENT_NUM))
    {
        return HI_INVALID_ARG;
    }

    anom_server_events = &(Session->anom_server.event_list);

    /*
    **  This is where we cycle through the current event stack.  If the event
    **  to be logged is already in the queue, then we increment the event
    **  count, before returning.  Otherwise, we fall through the loop and
    **  set the event before adding it to the queue and incrementing the
    **  pointer.
    */
    for(iCtr = 0; iCtr < anom_server_events->stack_count; iCtr++)
    {
        if(anom_server_events->stack[iCtr] == iEvent)
        {
            anom_server_events->events[iEvent].count++;
            return HI_SUCCESS;
        }
    }

    /*
    **  Initialize the event before putting it in the queue.
    */
    event = &(anom_server_events->events[iEvent]);
    event->event_info = &anom_server_event_info[iEvent];
    event->count = 1;
    event->data = data;
    event->free_data = free_data;

    /*
    **  We now add the event to the stack.
    */
    anom_server_events->stack[anom_server_events->stack_count] = iEvent;
    anom_server_events->stack_count++;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_eo_client_event_log::
*/
/**
**  This function logs client events during HttpInspect processing.
**
**  The idea behind this event logging is modularity, but at the same time
**  performance.  We accomplish this utilizing an optimized stack as an
**  index into the client event array, instead of walking a list for
**  already logged events.  The problem here is that we can't just log
**  every event that we've already seen, because this opens us up to a 
**  DOS.  So by using this method, we can quickly check if an event
**  has already been logged and deal appropriately.
**
**  @param Session   pointer to the HttpInspect session
**  @param iEvent    the event id for the client
**  @param data      pointer to the user data of the event
**  @param free_data pointer to a function to free the user data
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_INVALID_ARG invalid arguments
*/
int hi_eo_client_event_log(HI_SESSION *Session, int iEvent, void *data,
        void (*free_data)(void *))
{
    HI_CLIENT_EVENTS *client_events;
    HI_EVENT *event;
    int iCtr;

    /*
    **  Check the input variables for correctness
    */
    if(!Session || (iEvent >= HI_EO_CLIENT_EVENT_NUM))
    {
        return HI_INVALID_ARG;
    }

    client_events = &(Session->client.event_list);

    /*
    **  This is where we cycle through the current event stack.  If the event
    **  to be logged is already in the queue, then we increment the event
    **  count, before returning.  Otherwise, we fall through the loop and
    **  set the event before adding it to the queue and incrementing the
    **  pointer.
    */
    for(iCtr = 0; iCtr < client_events->stack_count; iCtr++)
    {
        if(client_events->stack[iCtr] == iEvent)
        {
            client_events->events[iEvent].count++;
            return HI_SUCCESS;
        }
    }

    /*
    **  Initialize the event before putting it in the queue.
    */
    event = &(client_events->events[iEvent]);
    event->event_info = &client_event_info[iEvent];
    event->count = 1;
    event->data = data;
    event->free_data = free_data;

    /*
    **  We now add the event to the stack.
    */
    client_events->stack[client_events->stack_count] = iEvent;
    client_events->stack_count++;

    return HI_SUCCESS;
}
