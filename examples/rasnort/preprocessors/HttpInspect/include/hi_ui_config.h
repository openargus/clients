/**
**  @file       httpinspect_configuration.h
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains the internal configuration structures
**              for HttpInspect.
**
**  This file holds the configuration constructs for the HttpInspect global
**  configuration and the server configurations.  It also contains the function
**  prototypes for accessing server configurations.
*/

#ifndef __HI_UI_CONFIG_H__
#define __HI_UI_CONFIG_H__

#include "hi_include.h"
#include "hi_util_kmap.h"

/*
**  Defines
*/
#define HI_UI_CONFIG_STATELESS 0
#define HI_UI_CONFIG_STATEFUL  1
#define HI_UI_CONFIG_MAX_PIPE  20

/**
**  Defines a search type for the server configurations in the
**  global configuration.  We want this generic so we can change
**  it easily if we change the search type.
*/
typedef KMAP SERVER_LOOKUP;

/**
**  This structure simply holds a value for on/off and whether
**  alert is on/off.  Should be used for many configure options.
*/
typedef struct s_HTTPINSPECT_CONF_OPT
{

    int on;     /**< if true, configuration option is on */
    int alert;  /**< if true, alert if option is found */

}  HTTPINSPECT_CONF_OPT;

/**
**  This is the configuration construct that holds the specific
**  options for a server.  Each unique server has it's own structure
**  and there is a global structure for servers that don't have
**  a unique configuration.
*/
typedef struct s_HTTPINSPECT_CONF
{
    int  port_count;
    char ports[65536];
    int  flow_depth;

    /*
    **  Unicode mapping for IIS servers
    */
    int  *iis_unicode_map;
    char *iis_unicode_map_filename;
    int  iis_unicode_codepage;

    int  long_dir;
    int  uri_only;
    int  no_alerts;
    
    /*
    **  Chunk encoding anomaly detection
    */
    int  chunk_length;

    /*
    **  pipeline requests
    */
    int no_pipeline;

    /*
    **  Enable non-strict (apache) URI handling.  This allows us to catch the
    **  non-standard URI parsing that apache does.
    */
    int non_strict;

    /*
    **  Allow proxy use for this server.
    */
    int allow_proxy;

    /*
    **  These are the URI encoding configurations
    */
    HTTPINSPECT_CONF_OPT ascii;
    HTTPINSPECT_CONF_OPT double_decoding;
    HTTPINSPECT_CONF_OPT u_encoding;
    HTTPINSPECT_CONF_OPT bare_byte;
    HTTPINSPECT_CONF_OPT base36;
    HTTPINSPECT_CONF_OPT utf_8;
    HTTPINSPECT_CONF_OPT iis_unicode;
    int                  non_rfc_chars[256];

    /*
    **  These are the URI normalization configurations
    */
    HTTPINSPECT_CONF_OPT multiple_slash;
    HTTPINSPECT_CONF_OPT iis_backslash;
    HTTPINSPECT_CONF_OPT directory;
    HTTPINSPECT_CONF_OPT apache_whitespace;
    HTTPINSPECT_CONF_OPT iis_delimiter;
    
}  HTTPINSPECT_CONF;

/**
**  This is the configuration for the global HttpInspect
**  configuration.  It contains the global aspects of the
**  configuration, a standard global default configuration,
**  and server configurations.
*/
typedef struct s_HTTPINSPECT_GLOBAL_CONF
{
    int              max_pipeline_requests;
    int              inspection_type;
    int              anomalous_servers;
    int              proxy_alert;

    /*
    **  These variables are for tracking the IIS
    **  Unicode Map configuration.
    */
    int              *iis_unicode_map;
    char             *iis_unicode_map_filename;
    int              iis_unicode_codepage;

    HTTPINSPECT_CONF global_server;
    SERVER_LOOKUP    *server_lookup;

}  HTTPINSPECT_GLOBAL_CONF;    

/*
**  Functions
*/
int hi_ui_config_init_global_conf(HTTPINSPECT_GLOBAL_CONF *GlobalConf);
int hi_ui_config_default(HTTPINSPECT_GLOBAL_CONF *GlobalConf);
int hi_ui_config_reset_global(HTTPINSPECT_GLOBAL_CONF *GlobalConf);
int hi_ui_config_reset_server(HTTPINSPECT_CONF *ServerConf);

int hi_ui_config_add_server(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                            unsigned long ServerIP, 
                            HTTPINSPECT_CONF *ServerConf);

int hi_ui_config_set_profile_apache(HTTPINSPECT_CONF *GlobalConf);
int hi_ui_config_set_profile_iis(HTTPINSPECT_CONF *GlobalConf, int *);
int hi_ui_config_set_profile_all(HTTPINSPECT_CONF *GlobalConf, int *);

#endif
