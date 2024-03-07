/**
**  @file       hi_ui_config.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains library calls to configure HttpInspect.
**
**  This file deals with configuring HttpInspect processing.  It contains
**  routines to set a default configuration, add server configurations, etc.
**
**  NOTES:
**
**  - 2.10.03:  Initial Developments.  DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "hi_return_codes.h"
#include "hi_util_xmalloc.h"
#include "hi_ui_server_lookup.h"
#include "hi_ui_config.h"

/*
**  NAME
**    hi_ui_config_init_global_conf::
*/
/**
**  Initialize the HttpInspect global configuration.
**
**  The main point of this function is to initialize the server
**  lookup type.  We also do things like memset, etc.
**
**  @param GlobalConf pointer to the global configuration
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL could not allocate memory
*/
int hi_ui_config_init_global_conf(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    int iRet;

    memset(GlobalConf, 0x00, sizeof(HTTPINSPECT_GLOBAL_CONF));

    if((iRet = hi_ui_server_lookup_init(&GlobalConf->server_lookup)))
    {
        return iRet;
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_config_default::
*/
/**
**  This function sets the global and the global_server default configuration.
**
**  In order to change the default configuration of HttpInspect, you must
**  change this function.
**
**  @param GlobalConf pointer to the global configuration structure
**  
**  @return integer
**
**  @retval HI_INVALID_ARG  Fatal Error.  Undefined pointer to GlobalConf
**  @retval HI_MEM_ALLOC_FAIL Fatal Error.  Memory Allocation Failed
*/
int hi_ui_config_default(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    if(GlobalConf == NULL)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Set Global Configurations
    */
    GlobalConf->inspection_type = HI_UI_CONFIG_STATELESS;

    /*
    **  Set Global Server Configurations
    */
    GlobalConf->global_server.port_count = 1;
    GlobalConf->global_server.ports[80] = 1;

    GlobalConf->global_server.flow_depth = 300;
    
    GlobalConf->global_server.chunk_length = 500000;

    GlobalConf->global_server.ascii.on = 1;

    GlobalConf->global_server.utf_8.on = 1;

    GlobalConf->global_server.multiple_slash.on = 1;

    GlobalConf->global_server.directory.on = 1;

    GlobalConf->global_server.apache_whitespace.on = 1;
    GlobalConf->global_server.apache_whitespace.alert = 1;

    GlobalConf->global_server.iis_delimiter.on = 1;
    GlobalConf->global_server.iis_delimiter.alert = 1;

    GlobalConf->global_server.non_strict = 1;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_config_reset_global::
*/
/**
**  This function resets the global parameters, THIS IS NOT THE GLOBAL
**  SERVER CONFIGURATION.
**
**  @param GlobalConf pointer to the global configuration structure
**
**  @return integer
**
**  @return HI_SUCCESS function successful
*/
int hi_ui_config_reset_global(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    GlobalConf->inspection_type = 0;
    GlobalConf->iis_unicode_map = 0;

    return HI_SUCCESS;
}
    
/*
**  NAME
**    hi_ui_config_reset_server::
*/
/**
**  This function resets a server construct.
**
**  @param ServerConf pointer to the HTTPINSPECT_CONF structure
**
**  @return integer
**
**  @return HI_SUCCESS function successful
*/
int hi_ui_config_reset_server(HTTPINSPECT_CONF *ServerConf)
{
    memset(ServerConf, 0x00, sizeof(HTTPINSPECT_CONF));

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_set_profile_apache::
*/
/**
**  Set an HTTPINSPECT_CONF to mimic apache configuration.
**
**  This sets a server configuration to imitate an apache web server,
**  and should reduce false positives against systems on which certain
**  attacks or evasions do not work.  We hope to still log an event,
**  but one that is less priority.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_apache(HTTPINSPECT_CONF *ServerConf)
{
    /*
    **  Reset the structure so we can assume zeros.
    */
    hi_ui_config_reset_server(ServerConf);

    ServerConf->flow_depth = 300;

    ServerConf->non_strict = 1;

    ServerConf->chunk_length = 500000; 

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->apache_whitespace.on = 1;
    ServerConf->apache_whitespace.alert = 1;

    ServerConf->utf_8.on = 1;

    return HI_SUCCESS;
}
    
/*
**  NAME
**    hi_ui_set_profile_iis::
*/
/**
**  Set an HTTPINSPECT_CONF to mimic IIS configuration.
**
**  This sets a server configuration to imitate an IIS web server,
**  and should reduce false positives against systems on which certain
**  attacks or evasions do not work.  We hope to still log an event,
**  but one that is less priority.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_iis(HTTPINSPECT_CONF *ServerConf,
                                 int *iis_unicode_map)
{
    if(iis_unicode_map == NULL)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Reset the structure so we can assume zeros.
    */
    hi_ui_config_reset_server(ServerConf);

    ServerConf->flow_depth = 300;

    ServerConf->iis_unicode_map = iis_unicode_map;

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->double_decoding.on    = 1;
    ServerConf->double_decoding.alert = 1;

    ServerConf->u_encoding.on         = 1;
    ServerConf->u_encoding.alert      = 1;

    ServerConf->bare_byte.on          = 1;
    ServerConf->bare_byte.alert       = 1;

    ServerConf->iis_unicode.on        = 1;
    ServerConf->iis_unicode.alert     = 1;

    ServerConf->iis_backslash.on      = 1;

    ServerConf->iis_delimiter.on      = 1;
    ServerConf->iis_delimiter.alert   = 1;

    ServerConf->apache_whitespace.on     = 1;
    ServerConf->apache_whitespace.alert  = 1;

    ServerConf->non_strict = 1;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_set_profile_all::
*/
/**
**  Set an HTTPINSPECT_CONF to catch all attacks and evasions.
**
**  This basically turns on all the tricks and most of the
**  alerts, so you won't miss anything that HttpInspect does.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_all(HTTPINSPECT_CONF *ServerConf,
                                 int *iis_unicode_map)
{
    if(iis_unicode_map == NULL)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Reset the structure so we can assume zeros.
    */
    hi_ui_config_reset_server(ServerConf);

    ServerConf->flow_depth   = 300;

    ServerConf->chunk_length = 500000; 

    ServerConf->iis_unicode_map = iis_unicode_map;

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->double_decoding.on    = 1;
    ServerConf->double_decoding.alert = 1;

    ServerConf->u_encoding.on         = 1;
    ServerConf->u_encoding.alert      = 1;

    ServerConf->bare_byte.on          = 1;
    ServerConf->bare_byte.alert       = 1;

    ServerConf->iis_unicode.on        = 1;
    ServerConf->iis_unicode.alert     = 1;

    ServerConf->iis_backslash.on      = 1;

    ServerConf->iis_delimiter.on      = 1;
    ServerConf->iis_delimiter.alert   = 1;

    ServerConf->apache_whitespace.on     = 1;
    ServerConf->apache_whitespace.alert  = 1;

    ServerConf->non_strict = 1;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_config_add_server::
*/
/**
**  Add a server config to the HttpInspect configuration.
**
**  This function takes an IP address of a server and an HttpInspect
**  configuration, and assigns the configuration to the IP address in
**  a lookup table.
**
**  @param GlobalConf pointer to the global configuration
**  @param ServerIp   the IP address of the server (in network byte order)
**  @param ServerConf pointer to the server configuration
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL could not allocate memory
**  @retval HI_NON_FATAL_ERR server has already been added
*/
int hi_ui_config_add_server(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                            unsigned long ServerIP, HTTPINSPECT_CONF *ServerConf)
{
    int iRet;

    if((iRet = hi_ui_server_lookup_add(GlobalConf->server_lookup, ServerIP, 
                                       ServerConf)))
    {
        /*
        **  Already added key will return a generic non-fatal
        **  error.
        */
        return iRet;
    }

    return HI_SUCCESS;

}
