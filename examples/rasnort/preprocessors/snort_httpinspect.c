/**
**  @file       snort_httpinspect.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file wraps the HttpInspect functionality for Snort
**              and starts the HttpInspect flow.
**
**  The file takes a Packet structure from the Snort IDS to start the
**  HttpInspect flow.  This also uses the Stream Interface Module which
**  is also Snort-centric.  Mainly, just a wrapper to HttpInspect               
**  functionality, but a key part to starting the basic flow.
**
**  The main bulk of this file is taken up with user configuration and
**  parsing.  The reason this is so large is because HttpInspect takes
**  very detailed configuration parameters for each specified server.
**  Hopefully every web server that is out there can be emulated
**  with these configuration options.
**  
**  The main functions of note are:
**    - HttpInspectSnortConf::this is the configuration portion
**    - SnortHttpInspect::this is the actual inspection flow
**    - LogEvents:this is where we log the HttpInspect events
**
**  NOTES:
**
**  - 2.11.03:  Initial Development.  DJR
*/
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "snort.h"
#include "detect.h"
#include "decode.h"
#include "log.h"
#include "event.h"
#include "generators.h"
#include "debug.h"
#include "plugbase.h"
#include "util.h"
#include "event_wrapper.h"

#include "hi_return_codes.h"
#include "hi_ui_config.h"
#include "hi_ui_iis_unicode_map.h"
#include "hi_si.h"
#include "hi_mi.h"
#include "hi_norm.h"

extern PV pv;

#define MAX_FILENAME    1000

/**
**  The definition of the configuration separators in the snort.conf
**  configure line.
*/
#define CONF_SEPARATORS " \t\n\r"

/*
**  These are the definitions of the parser section delimiting 
**  keywords to configure HttpInspect.  When one of these keywords
**  are seen, we begin a new section.
*/
#define GLOBAL        "global"
#define GLOBAL_SERVER "global_server"
#define SERVER        "server"

/*
**  GLOBAL subkeywords.
*/
/**
**  Takes an integer arugment
*/
#define MAX_PIPELINE  "max_pipeline"
/**
**  Specifies whether to alert on anomalous
**  HTTP servers or not.
*/
#define ANOMALOUS_SERVERS "detect_anomalous_servers"
/**
**  Alert on general proxy use
*/
#define PROXY_ALERT "proxy_alert"
/**
**  Takes an inspection type argument
**  stateful or stateless
*/
#define INSPECT_TYPE  "inspection_type"
#define DEFAULT       "default"

/*
**  GLOBAL subkeyword values
*/
#define INSPECT_TYPE_STATELESS "stateless"
#define INSPECT_TYPE_STATEFUL  "stateful"

/*
**  SERVER subkeywords.
*/
#define PORTS             "ports"
#define FLOW_DEPTH        "flow_depth"
#define IIS_UNICODE_MAP   "iis_unicode_map"
#define CHUNK_LENGTH      "chunk_length"
#define PIPELINE          "no_pipeline_req"
#define ASCII             "ascii"
#define DOUBLE_DECODE     "double_decode"
#define U_ENCODE          "u_encode"
#define BARE_BYTE         "bare_byte"
#define BASE36            "base36"
#define UTF_8             "utf_8"
#define IIS_UNICODE       "iis_unicode"
#define NON_RFC_CHAR      "non_rfc_char"
#define MULTI_SLASH       "multi_slash"
#define IIS_BACKSLASH     "iis_backslash"
#define DIRECTORY         "directory"
#define APACHE_WS         "apache_whitespace"
#define IIS_DELIMITER     "iis_delimiter"
#define PROFILE           "profile"
#define NON_STRICT        "non_strict"
#define ALLOW_PROXY       "allow_proxy_use"
#define OVERSIZE_DIR      "oversize_dir_length"
#define INSPECT_URI_ONLY  "inspect_uri_only"
#define GLOBAL_ALERT      "no_alerts"

/*
**  Alert subkeywords
*/
#define BOOL_YES     "yes"
#define BOOL_NO      "no"

/*
**  PROFILE subkeywords
*/
#define APACHE        "apache"
#define IIS           "iis"
#define ALL           "all"

/*
**  Port list delimiters
*/
#define START_PORT_LIST "{"
#define END_PORT_LIST   "}"

/*
**  Keyword for the default server configuration
*/
#define SERVER_DEFAULT "default"

/*
**  NAME
**    ProcessGlobalAlert::
*/
/**
**  Process the global alert keyword.
**
**  There is no arguments to this keyword, because you can only turn
**  all the alerts off.  As of now, we aren't going to support turning
**  all the alerts on.
**
**  @param GlobalConf  pointer to the global configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the lenght of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
/*
static int ProcessGlobalAlert(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                              char *ErrorString, int ErrStrLen)
{
    GlobalConf->no_alerts = 1;

    return 0;
}
*/

/* 
**  NAME
**    ProcessMaxPipeline::
*/
/**
**  Process the max pipeline configuration.
**
**  This sets the maximum number of pipeline requests that we
**  will buffer while waiting for responses, before inspection.
**  There is a maximum limit on this, but we can track a user
**  defined amount.
**
**  @param GlobalConf  pointer to the global configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the lenght of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessMaxPipeline(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                              char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd = NULL;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to token '%s'.", MAX_PIPELINE);

        return -1;
    }

    GlobalConf->max_pipeline_requests = strtol(pcToken, &pcEnd, 10);

    /*
    **  Let's check to see if the entire string was valid.
    **  If there is an address here, then there was an
    **  invalid character in the string.
    */
    if(*pcEnd)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to token '%s'.  Must be a positive "
                "number between 0 and %d.", MAX_PIPELINE,
                HI_UI_CONFIG_MAX_PIPE);

        return -1;
    }

    if(GlobalConf->max_pipeline_requests < 0 || 
       GlobalConf->max_pipeline_requests > HI_UI_CONFIG_MAX_PIPE)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to token '%s'.  Must be a positive "
                "number between 0 and %d.", MAX_PIPELINE, HI_UI_CONFIG_MAX_PIPE);

        return -1;
    }

    return 0;
}

/* 
**  NAME
**    ProcessInspectType::
*/
/**
**  Process the type of inspection.
**
**  This sets the type of inspection for HttpInspect to do.
**
**  @param GlobalConf  pointer to the global configuration
**  @param ErrorString error string buffer
**
**  @param ErrStrLen   the lenght of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessInspectType(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                              char *ErrorString, int ErrStrLen)
{
    char *pcToken;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to token '%s'.", INSPECT_TYPE);

        return -1;
    }

    if(!strcmp(INSPECT_TYPE_STATEFUL, pcToken))
    {
        GlobalConf->inspection_type = HI_UI_CONFIG_STATEFUL;

        /*
        **  We don't support this option yet, so we'll give an error and
        **  bail.
        */
        snprintf(ErrorString, ErrStrLen,
                 "Stateful HttpInspect processing is not yet available.  "
                 "Please use stateless processing for now.");

        return -1;
    }
    else if(!strcmp(INSPECT_TYPE_STATELESS, pcToken))
    {
        GlobalConf->inspection_type = HI_UI_CONFIG_STATELESS;
    }
    else
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to token '%s'.  Must be either "
                "'%s' or '%s'.", INSPECT_TYPE, INSPECT_TYPE_STATEFUL,
                INSPECT_TYPE_STATELESS);

        return -1;
    }

    return 0;
}

static int ProcessIISUnicodeMap(int **iis_unicode_map, 
                                char **iis_unicode_map_filename,
                                int *iis_unicode_map_codepage,
                                char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iRet;
    char filename[MAX_FILENAME];
    char *pcEnd;
    int  iCodeMap;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                 "No argument to token '%s'.", IIS_UNICODE_MAP);

        return -1;
    }

    /*
    **  If an absolute path is specified, then use that.
    */
#ifndef WIN32
    if(pcToken[0] == '/')
    {
        iRet = snprintf(filename, sizeof(filename), "%s", pcToken);
    }
    else
    {
        /*
        **  Set up the file name directory
        */
        if(pv.config_dir[strlen(pv.config_dir)-1] == '/')
        {
            iRet = snprintf(filename, sizeof(filename), 
                            "%s%s", pv.config_dir, pcToken);
        }
        else
        {
            iRet = snprintf(filename, sizeof(filename),
                            "%s/%s", pv.config_dir, pcToken);
        }
    }
#else
    if(strlen(pcToken)>3 && pcToken[1]==':' && pcToken[2]=='\\')
    {
        iRet = snprintf(filename, sizeof(filename), "%s", pcToken);
    }
    else
    {
        /*
        **  Set up the file name directory
        */
        if(pv.config_dir[strlen(pv.config_dir)-1] == '\\' ||
           pv.config_dir[strlen(pv.config_dir)-1] == '/' )
        {
            iRet = snprintf(filename, sizeof(filename), 
                            "%s%s", pv.config_dir, pcToken);
        }
        else
        {
            iRet = snprintf(filename, sizeof(filename),
                            "%s\\%s", pv.config_dir, pcToken);
        }
    }
#endif

    if(iRet < 0)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Filename too long for token '%s'.", IIS_UNICODE_MAP);

        return -1;
    }

    /*
    **  Set the filename
    */
    *iis_unicode_map_filename = strdup(filename);
    if(*iis_unicode_map_filename == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Could not strdup() '%s' filename.",
                 IIS_UNICODE_MAP);

        return -1;
    }

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                 "No codemap to select from IIS Unicode Map file.");

        return -1;
    }

    /*
    **  Grab the unicode codemap to use
    */
    iCodeMap = strtol(pcToken, &pcEnd, 10);
    if(*pcEnd || iCodeMap < 0)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Invalid IIS codemap argument.");

        return -1;
    }

    /*
    **  Set the codepage
    */
    *iis_unicode_map_codepage = iCodeMap;

    /*
    **  Assume that the pcToken we now have is the filename of the map
    **  table.
    */
    if((iRet = hi_ui_parse_iis_unicode_map(iis_unicode_map, 
                                           filename, iCodeMap)))
    {
        if(iRet == HI_INVALID_FILE)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Invalid file name for IIS Unicode Map file.");
        }
        else if(iRet == HI_FATAL_ERR)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Did not find specified IIS Unicode codemap in "
                     "the specified IIS Unicode Map file.");
        }
        else
        {
            snprintf(ErrorString, ErrStrLen,
                     "There was an error while parsing the IIS Unicode "
                     "Map file.");
        }

        return -1;
    }

    return 0;
}

static int ProcessOversizeDir(HTTPINSPECT_CONF *ServerConf,
                              char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iDirLen;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                 "No argument to token '%s'.", OVERSIZE_DIR);

        return -1;
    }

    /*
    **  Grab the oversize directory length
    */
    iDirLen = strtol(pcToken, &pcEnd, 10);
    if(*pcEnd || iDirLen < 0)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Invalid argument to token '%s'.", OVERSIZE_DIR);
        
        return -1;
    }

    ServerConf->long_dir = iDirLen;

    return 0;
}

/*
**  NAME
**      ProcessGlobalConf::
*/
/**
**  This is where we process the global configuration for HttpInspect.
**
**  We set the values of the global configuraiton here.  Any errors that
**  are encountered are specified in the error string and the type of
**  error is returned through the return code, i.e. fatal, non-fatal.
**
**  The configuration options that are dealt with here are:
**      - global_alert
**          This tells us whether to do any internal alerts or not, on
**          a global scale.
**      - max_pipeline
**          Tells HttpInspect how many pipeline requests to buffer looking
**          for a response before inspection.
**      - inspection_type
**          What type of inspection for HttpInspect to do, stateless or
**          stateful.
**
**  @param GlobalConf  pointer to the global configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the lenght of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessGlobalConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                             char *ErrorString, int ErrStrLen)
{
    int  iRet;
    char *pcToken;
    int  iTokens = 0;

    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        /*
        **  Show that we at least got one token
        */
        iTokens = 1;

        /*
        **  Search for configuration keywords
        */
        if(!strcmp(MAX_PIPELINE, pcToken))
        {
            if((iRet = ProcessMaxPipeline(GlobalConf, ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(INSPECT_TYPE, pcToken))
        {
            if((iRet = ProcessInspectType(GlobalConf, ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(IIS_UNICODE_MAP, pcToken))
        {
            if((iRet = ProcessIISUnicodeMap(&GlobalConf->iis_unicode_map,
                                         &GlobalConf->iis_unicode_map_filename,
                                            &GlobalConf->iis_unicode_codepage,
                                            ErrorString,ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(ANOMALOUS_SERVERS, pcToken))
        {
            /*
            **  This is easy to configure since we just look for the token
            **  and turn on the option.
            */
            GlobalConf->anomalous_servers = 1;
        }
        else if(!strcmp(PROXY_ALERT, pcToken))
        {
            GlobalConf->proxy_alert = 1;
        }
        else
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid keyword '%s' for '%s' configuration.", 
                     pcToken, GLOBAL);

            return -1;
        }
    }

    /*
    **  If there are not any tokens to the configuration, then
    **  we let the user know and log the error.  return non-fatal
    **  error.
    */
    if(!iTokens)
    {
        snprintf(ErrorString, ErrStrLen,
                "No tokens to '%s' configuration.", GLOBAL);

        return -1;
    }

    /*
    **  Let's check to make sure that we get a default IIS Unicode Codemap
    */
    if(!GlobalConf->iis_unicode_map)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Global configuration must contain an IIS Unicode Map "
                 "configuration.  Use token '%s'.", IIS_UNICODE_MAP);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessProfile::
*/
/**
**  Process the PROFILE configuration.
**
**  This function verifies that the argument to the profile configuration
**  is valid.  We also check to make sure there is no additional
**  configuration after the PROFILE.  This is no allowed, so we
**  alert on that fact.
**
**  @param ServerConf  pointer to the server configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessProfile(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                          HTTPINSPECT_CONF *ServerConf,
                          char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iRet;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to '%s'.", PROFILE);

        return -1;
    }

    /*
    **  Load the specific type of profile
    */
    if(!strcmp(APACHE, pcToken))
    {
        if((iRet = hi_ui_config_set_profile_apache(ServerConf)))
        {
            if(iRet == HI_MEM_ALLOC_FAIL)
            {
                snprintf(ErrorString, ErrStrLen,
                        "Memory allocation failed while setting the '%s' "
                        "profile.", APACHE);

                return -1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                        "Undefined error code for set_profile_apache.");

                return -1;
            }
        }
    }
    else if(!strcmp(IIS, pcToken))
    {
        if((iRet = hi_ui_config_set_profile_iis(ServerConf, 
                                                GlobalConf->iis_unicode_map)))
        {
            if(iRet == HI_MEM_ALLOC_FAIL)
            {
                snprintf(ErrorString, ErrStrLen,
                        "Memory allocation failed while setting the '%s' "
                        "profile.", IIS);

                return -1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                        "Undefined error code for set_profile_iis.");

                return -1;
            }
        }
    }
    else if(!strcmp(ALL, pcToken))
    {
        if((iRet = hi_ui_config_set_profile_all(ServerConf,
                                                GlobalConf->iis_unicode_map)))
        {
            if(iRet == HI_MEM_ALLOC_FAIL)
            {
                snprintf(ErrorString, ErrStrLen,
                        "Memory allocation failed while setting the '%s' "
                        "profile.", ALL);

                return -1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                        "Undefined error code for set_profile_all.");

                return -1;
            }
        }
    }
    else
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid profile argument '%s'.", pcToken);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessPorts::
*/
/**
**  Process the port list for the server configuration.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ServerConf  pointer to the server configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessPorts(HTTPINSPECT_CONF *ServerConf,
                        char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iPort;
    int  iEndPorts = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid port list format.");

        return -1;
    }

    if(strcmp(START_PORT_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a port list with the '%s' token.",
                START_PORT_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_PORT_LIST, pcToken))
        {
            iEndPorts = 1;
            break;
        }

        iPort = strtol(pcToken, &pcEnd, 10);

        /*
        **  Validity check for port
        */
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.");

            return -1;
        }

        if(iPort < 0 || iPort > 65535)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.  Must be between 0 and "
                    "65535.");

            return -1;
        }

        ServerConf->ports[iPort] = 1;

        if(ServerConf->port_count < 65536)
            ServerConf->port_count++;
    }

    if(!iEndPorts)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                PORTS, END_PORT_LIST);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessFlowDepth::
*/
/**
**  Configure the flow depth for a server.
**
**  Check that the value for flow depth is within bounds
**  and is a valid number.
**
**  @param ServerConf  pointer to the server configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessFlowDepth(HTTPINSPECT_CONF *ServerConf,
                            char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iFlowDepth;
    char *pcEnd;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to '%s' token.", FLOW_DEPTH);

        return -1;
    }

    iFlowDepth = strtol(pcToken, &pcEnd, 10);
    if(*pcEnd)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to '%s'.", FLOW_DEPTH);

        return -1;
    }

    if(iFlowDepth < 0 || iFlowDepth > 1460)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to '%s'.  Must be between 0 and "
                "1460.", FLOW_DEPTH);

        return -1;
    }

    ServerConf->flow_depth = iFlowDepth;

    return 0;
}

/*
**  NAME
**    ProcessChunkLength::
*/
/**
**  Process and verify the chunk length for the server configuration.
**  
**  @param ServerConf  pointer to the server configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessChunkLength(HTTPINSPECT_CONF *ServerConf,
                              char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iChunkLength;
    char *pcEnd;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to '%s' token.", CHUNK_LENGTH);

        return -1;
    }

    iChunkLength = strtol(pcToken, &pcEnd, 10);
    if(*pcEnd)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to '%s'.", CHUNK_LENGTH);

        return -1;
    }

    if(iChunkLength < 0)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to '%s'.", CHUNK_LENGTH);

        return -1;
    }

    ServerConf->chunk_length = iChunkLength;

    return 0;
}

/*
**  NAME
**    ProcessConfOpt::
*/
/**
**  Set the CONF_OPT on and alert fields.
**
**  We check to make sure of valid parameters and then
**  set the appropriate fields.  Not much more to it, than
**  that.
**
**  @param ConfOpt  pointer to the configuration option
**  @param Option   character pointer to the option being configured
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessConfOpt(HTTPINSPECT_CONF_OPT *ConfOpt, char *Option,
                          char *ErrorString, int ErrStrLen)
{
    char *pcToken;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No argument to token '%s'.", Option);

        return -1;
    }

    /*
    **  Check for the alert value
    */
    if(!strcmp(BOOL_YES, pcToken))
    {
        ConfOpt->alert = 1;
    }
    else if(!strcmp(BOOL_NO, pcToken))
    {
        ConfOpt->alert = 0;
    }
    else
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid argument to token '%s'.", Option);

        return -1;
    }

    ConfOpt->on = 1;

    return 0;
}

/*
**  NAME
**    ProcessNonRfcChar::
*/
/***
**  Configure any characters that the user wants alerted on in the
**  URI.
**
**  This function allocates the memory for CONF_OPT per character and
**  configures the alert option.
**
**  @param ConfOpt  pointer to the configuration option
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessNonRfcChar(HTTPINSPECT_CONF *ServerConf,
                             char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iChar;
    int  iEndChar = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid '%s' list format.", NON_RFC_CHAR);

        return -1;
    }

    if(strcmp(START_PORT_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a '%s' list with the '%s' token.",
                NON_RFC_CHAR, START_PORT_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_PORT_LIST, pcToken))
        {
            iEndChar = 1;
            break;
        }

        iChar = strtol(pcToken, &pcEnd, 16);
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid argument to '%s'.  Must be a single "
                    "character.", NON_RFC_CHAR);

            return -1;
        }

        if(iChar < 0 || iChar > 255)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid character value to '%s'.  Must be a single "
                    "character no greater than 255.", NON_RFC_CHAR);

            return -1;
        }

        ServerConf->non_rfc_chars[iChar] = 1;
    }

    if(!iEndChar)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                NON_RFC_CHAR, END_PORT_LIST);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessServerConf::
*/
/**
**  Process the global server configuration.
**
**  Take the configuration and translate into the global server
**  configuration.  We also check for any configuration errors and
**  invalid keywords.
**
**  @param ServerConf  pointer to the server configuration
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessServerConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                             HTTPINSPECT_CONF *ServerConf,
                             char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iRet;
    int  iPorts = 0;
    HTTPINSPECT_CONF_OPT *ConfOpt;

    /*
    **  Check for profile keyword first, it's the only place in the
    **  configuration that is correct.
    */
    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen,
                "No tokens to '%s' configuration.", GLOBAL);

        return 1;
    }

    if(!strcmp(PROFILE, pcToken))
    {
        if((iRet = ProcessProfile(GlobalConf, ServerConf,
                                  ErrorString, ErrStrLen)))
        {
            return iRet;
        }

        pcToken = strtok(NULL, CONF_SEPARATORS);
        if(pcToken == NULL)
        {
            snprintf(ErrorString, ErrStrLen,
                     "No port list to the profile token.");

            return -1;
        }

        do
        {
            if(!strcmp(PORTS, pcToken))
            {
                if((iRet = ProcessPorts(ServerConf, 
                                        ErrorString, ErrStrLen)))
                {
                    return iRet;
                }

                iPorts = 1;
            }
            else if(!strcmp(IIS_UNICODE_MAP, pcToken))
            {
                if((iRet = ProcessIISUnicodeMap(&ServerConf->iis_unicode_map,
                                         &ServerConf->iis_unicode_map_filename,
                                             &ServerConf->iis_unicode_codepage,
                                                ErrorString,ErrStrLen)))
                {
                    return -1;
                }
            }
            else if(!strcmp(ALLOW_PROXY, pcToken))
            {
                ServerConf->allow_proxy = 1;
            }
            else if(!strcmp(FLOW_DEPTH, pcToken))
            {
                if((iRet = ProcessFlowDepth(ServerConf, 
                                            ErrorString, ErrStrLen)))
                {
                    return iRet;
                }
            }
            else if(!strcmp(GLOBAL_ALERT, pcToken))
            {
                ServerConf->no_alerts = 1;
            }
            else if(!strcmp(OVERSIZE_DIR, pcToken))
            {
                if((iRet = ProcessOversizeDir(ServerConf, 
                                              ErrorString, ErrStrLen)))
                {
                    return iRet;
                }
 
            }
            else if(!strcmp(INSPECT_URI_ONLY, pcToken))
            {
                ServerConf->uri_only = 1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                         "Invalid token while configuring the profile token.  "
                         "The only allowed tokens when configuring profiles "
                         "are: '%s', '%s', '%s', '%s', '%s', '%s', and '%s'.",
                         PORTS,IIS_UNICODE_MAP, ALLOW_PROXY, FLOW_DEPTH,
                         GLOBAL_ALERT, OVERSIZE_DIR, INSPECT_URI_ONLY);

                return -1;
            }

        } while((pcToken = strtok(NULL, CONF_SEPARATORS)));

        if(!iPorts)
        {
            snprintf(ErrorString, ErrStrLen,
                     "No port list to the profile token.");

            return -1;
        }

        return 0;
    }

    /*
    **  If there is no profile configuration then we go into the hard-core
    **  configuration.
    */
    do
    {
        if(!strcmp(PORTS, pcToken))
        {
            if((iRet = ProcessPorts(ServerConf, 
                                    ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(FLOW_DEPTH, pcToken))
        {
            if((iRet = ProcessFlowDepth(ServerConf, 
                                        ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(IIS_UNICODE_MAP, pcToken))
        {
            if((iRet = ProcessIISUnicodeMap(&ServerConf->iis_unicode_map,
                                         &ServerConf->iis_unicode_map_filename,
                                            &ServerConf->iis_unicode_codepage,
                                            ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(CHUNK_LENGTH, pcToken))
        {
            if((iRet = ProcessChunkLength(ServerConf,ErrorString,ErrStrLen )))
            {
                return iRet;
            }
        }
        else if(!strcmp(PIPELINE, pcToken))
        {
            ServerConf->no_pipeline = 1;
        }
        else if(!strcmp(NON_STRICT, pcToken))
        {
            ServerConf->non_strict = 1;
        }
        else if(!strcmp(ALLOW_PROXY, pcToken))
        {
            ServerConf->allow_proxy = 1;
        }
        else if(!strcmp(GLOBAL_ALERT, pcToken))
        {
            ServerConf->no_alerts = 1;
        }
        else if(!strcmp(OVERSIZE_DIR, pcToken))
        {
            if((iRet = ProcessOversizeDir(ServerConf, 
                                          ErrorString, ErrStrLen)))
            {
                return iRet;
            }
 
        }
        else if(!strcmp(INSPECT_URI_ONLY, pcToken))
        {
            ServerConf->uri_only = 1;
        }

        /*
        **  Start the CONF_OPT configurations.
        */
        else if(!strcmp(ASCII, pcToken))
        {
            ConfOpt = &ServerConf->ascii;
            if((iRet = ProcessConfOpt(ConfOpt, ASCII, 
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(UTF_8, pcToken))
        {
            /*
            **  In order for this to work we also need to set ASCII
            */
            ServerConf->ascii.on    = 1;

            ConfOpt = &ServerConf->utf_8;
            if((iRet = ProcessConfOpt(ConfOpt, UTF_8,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(IIS_UNICODE, pcToken))
        {
            if(ServerConf->iis_unicode_map == NULL)
            {
                ServerConf->iis_unicode_map = GlobalConf->iis_unicode_map;
            }

            /*
            **  We need to set up:
            **    - ASCII
            **    - DOUBLE_DECODE
            **    - U_ENCODE
            **    - BARE_BYTE
            **    - IIS_UNICODE
            **    - BASE36
            */
            ServerConf->ascii.on           = 1;

            ConfOpt = &ServerConf->iis_unicode;
            if((iRet = ProcessConfOpt(ConfOpt, IIS_UNICODE,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(DOUBLE_DECODE, pcToken))
        {
            ServerConf->ascii.on             = 1;

            ConfOpt = &ServerConf->double_decoding;
            if((iRet = ProcessConfOpt(ConfOpt, DOUBLE_DECODE,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(U_ENCODE, pcToken))
        {
            /*
            **  With %U encoding, we don't want base36 on.
            */
            ServerConf->base36.on = 0;
            ServerConf->base36.alert = 0;

            /*
            **  We set the unicode map to default if it's not already
            **  set.
            */
            if(ServerConf->iis_unicode_map == NULL)
            {
                ServerConf->iis_unicode_map = GlobalConf->iis_unicode_map;
            }

            ConfOpt = &ServerConf->u_encoding;
            if((iRet = ProcessConfOpt(ConfOpt, U_ENCODE,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(BARE_BYTE, pcToken))
        {
            ConfOpt = &ServerConf->bare_byte;
            if((iRet = ProcessConfOpt(ConfOpt, BARE_BYTE,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(BASE36, pcToken))
        {
            ServerConf->ascii.on      = 1;

            /*
            **  With Base36 encoding, we don't want to have %U encoding
            **  turned on.
            */
            ServerConf->u_encoding.on    = 0;
            ServerConf->u_encoding.alert = 0;

            ConfOpt = &ServerConf->base36;
            if((iRet = ProcessConfOpt(ConfOpt, BASE36,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(NON_RFC_CHAR, pcToken))
        {
            if((iRet = ProcessNonRfcChar(ServerConf, ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(MULTI_SLASH, pcToken))
        {
            ConfOpt = &ServerConf->multiple_slash;
            if((iRet = ProcessConfOpt(ConfOpt, MULTI_SLASH,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(IIS_BACKSLASH, pcToken))
        {
            ConfOpt = &ServerConf->iis_backslash;
            if((iRet = ProcessConfOpt(ConfOpt, IIS_BACKSLASH,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(DIRECTORY, pcToken))
        {
            ConfOpt = &ServerConf->directory;
            if((iRet = ProcessConfOpt(ConfOpt, DIRECTORY,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(APACHE_WS, pcToken))
        {
            ConfOpt = &ServerConf->apache_whitespace;
            if((iRet = ProcessConfOpt(ConfOpt, APACHE_WS,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else if(!strcmp(IIS_DELIMITER, pcToken))
        {
            ConfOpt = &ServerConf->iis_delimiter;
            if((iRet = ProcessConfOpt(ConfOpt, IIS_DELIMITER,
                                      ErrorString, ErrStrLen)))
            {
                return iRet;
            }
        }
        else
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid keyword '%s' for server configuration.",
                     pcToken);

            return -1;
        }
    } 
    while((pcToken = strtok(NULL, CONF_SEPARATORS)));
        
    return 0;
}

static int PrintConfOpt(HTTPINSPECT_CONF_OPT *ConfOpt, char *Option)
{
    if(!ConfOpt || !Option)
    {
        return HI_INVALID_ARG;
    }

    if(ConfOpt->on)
    {
        LogMessage("      %s: YES alert: %s\n", Option,
               ConfOpt->alert ? "YES" : "NO");
    }
    else
    {
        LogMessage("      %s: OFF\n", Option);
    }

    return 0;
}

static int PrintServerConf(HTTPINSPECT_CONF *ServerConf)
{
    int iCtr;
    int iNonRfcChar = 0;

    if(!ServerConf)
    {
        return HI_INVALID_ARG;
    }

    LogMessage("      Ports: ");

    /*
    **  Print out all the applicable ports.
    */
    for(iCtr = 0; iCtr < 65536; iCtr++)
    {
        if(ServerConf->ports[iCtr])
        {
            LogMessage("%d ", iCtr);
        }
    }

    LogMessage("\n");

    LogMessage("      Flow Depth: %d\n", ServerConf->flow_depth);
    LogMessage("      Max Chunk Length: %d\n", ServerConf->chunk_length);
    LogMessage("      Inspect Pipeline Requests: %s\n",
               ServerConf->no_pipeline ? "NO" : "YES");
    LogMessage("      URI Discovery Strict Mode: %s\n",
               ServerConf->non_strict ? "NO" : "YES");
    LogMessage("      Allow Proxy Usage: %s\n",
               ServerConf->allow_proxy ? "YES" : "NO");
    LogMessage("      Disable Alerting: %s\n", 
               ServerConf->no_alerts ? "YES":"NO");
    LogMessage("      Oversize Dir Length: %d\n",
               ServerConf->long_dir);
    LogMessage("      Only inspect URI: %s\n",
               ServerConf->uri_only ? "YES" : "NO");

    PrintConfOpt(&ServerConf->ascii, "Ascii");
    PrintConfOpt(&ServerConf->double_decoding, "Double Decoding");
    PrintConfOpt(&ServerConf->u_encoding, "%U Encoding");
    PrintConfOpt(&ServerConf->bare_byte, "Bare Byte");
    PrintConfOpt(&ServerConf->base36, "Base36");
    PrintConfOpt(&ServerConf->utf_8, "UTF 8");
    PrintConfOpt(&ServerConf->iis_unicode, "IIS Unicode");
    PrintConfOpt(&ServerConf->multiple_slash, "Multiple Slash");
    PrintConfOpt(&ServerConf->iis_backslash, "IIS Backslash");
    PrintConfOpt(&ServerConf->directory, "Directory");
    PrintConfOpt(&ServerConf->apache_whitespace, "Apache WhiteSpace");
    PrintConfOpt(&ServerConf->iis_delimiter, "IIS Delimiter");

    if(ServerConf->iis_unicode_map_filename)
    {
        LogMessage("      IIS Unicode Map Filename: %s\n",
                   ServerConf->iis_unicode_map_filename);
        LogMessage("      IIS Unicode Map Codepage: %d\n",
                   ServerConf->iis_unicode_codepage);
    }
    else if(ServerConf->iis_unicode_map)
    {
        LogMessage("      IIS Unicode Map: "                                    
                   "GLOBAL IIS UNICODE MAP CONFIG\n");
    }
    else
    {
        LogMessage("      IIS Unicode Map:  NOT CONFIGURED\n");
    }

    /*
    **  Print out the non-rfc chars
    */
    LogMessage("      Non-RFC Compliant Characters: ");
    for(iCtr = 0; iCtr < 256; iCtr++)
    {
        if(ServerConf->non_rfc_chars[iCtr])
        {
            LogMessage("0x%.2x ", (u_char)iCtr);
            iNonRfcChar = 1;
        }
    }

    if(!iNonRfcChar)
    {
        LogMessage("NONE");
    }

    LogMessage("\n");

    return 0;
}

static int ProcessUniqueServerConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf,
                             char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    unsigned long Ip;
    struct in_addr ip_addr;
    HTTPINSPECT_CONF *ServerConf;
    static int s_iDefaultServer = 0;
    int iRet;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "No arguments to '%s' token.", SERVER);

        return -1;
    }

    /*
    **  Check for the default configuration first
    */
    if(!strcmp(SERVER_DEFAULT, pcToken))
    {
        if(s_iDefaultServer)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Cannot configure '%s' settings more than once.",
                    GLOBAL_SERVER);

            return -1;
        }

        s_iDefaultServer = 1;

        ServerConf = &GlobalConf->global_server;

        /*
        **  Reset the global server configuration
        */
        if(hi_ui_config_reset_server(ServerConf))
        {
            snprintf(ErrorString, ErrStrLen,
                    "Cannot reset the HttpInspect default server configuration.");

            return -1;
        }

        if((iRet = ProcessServerConf(GlobalConf, ServerConf, 
                                     ErrorString, ErrStrLen)))
        {
            return iRet;
        }

        /*
        **  Start writing out the Default Server Config
        */
        LogMessage("    DEFAULT SERVER CONFIG:\n");
    }
    else
    {
        /*
        **  Convert string to IP address
        */
        Ip = inet_addr(pcToken);
        if(Ip == INADDR_NONE)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid IP to '%s' token.", SERVER);

            return -1;
        }

        /*
        **  allocate the memory for the server configuration
        */
        ServerConf = malloc(sizeof(HTTPINSPECT_CONF));
        if(!ServerConf)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Could not allocate memory for server configuration.");

            return -1;
        }

        memset(ServerConf, 0x00, sizeof(HTTPINSPECT_CONF));

        if((iRet = ProcessServerConf(GlobalConf, ServerConf, 
                                     ErrorString, ErrStrLen)))
        {
            return iRet;
        }

        if((iRet = hi_ui_config_add_server(GlobalConf, Ip, ServerConf)))
        {
            /*
            **  Check for already added servers
            */
            if(iRet == HI_NONFATAL_ERR)
            {
                snprintf(ErrorString, ErrStrLen,
                        "Duplicate server configuration.");

                return -1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                        "Error when adding server configuration.");

                return -1;
            }
        }

        ip_addr.s_addr = Ip;

        /*
        **  Print out the configuration header
        */
        LogMessage("    SERVER: %s\n", inet_ntoa(ip_addr));
    }

    /*
    **  Finish printing out the server configuration
    */
    PrintServerConf(ServerConf);

    return 0;
}

static int PrintGlobalConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    LogMessage("HttpInspect Config:\n");

    LogMessage("    GLOBAL CONFIG\n");
    LogMessage("      Max Pipeline Requests:    %d\n", 
               GlobalConf->max_pipeline_requests);
    LogMessage("      Inspection Type:          %s\n",
               GlobalConf->inspection_type ? "STATEFUL" : "STATELESS");
    LogMessage("      Detect Proxy Usage:       %s\n",
               GlobalConf->proxy_alert ? "YES" : "NO");
    LogMessage("      IIS Unicode Map Filename: %s\n",
               GlobalConf->iis_unicode_map_filename);
    LogMessage("      IIS Unicode Map Codepage: %d\n",
               GlobalConf->iis_unicode_codepage);

    return 0;
}



/*
**  NAME
**    HttpInspectSnortConf::
*/
/**
**  This function takes the HttpInspect configuration line from the 
**  snort.conf and creats an HttpInspect configuration.
**
**  This routine takes care of the snort specific configuration processing
**  and calls the generic routines to add specific server configurations.
**  It sets the configuration structure elements in this routine.
**
**  The ErrorString is passed in as a pointer, and the ErrStrLen tells
**  us the length of the pointer.
**
**  @param GlobalConf  a pointer to the global configuration.
**  @param args        a pointer to argument string.
**  @param iGlobal     whether this is the global configuration or a server
**  @param ErrorString a pointer for an error string.
**  @param ErrStrLen   the length of the error string.
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 success
**  @retval  1 generic non-fatal error
**  @retval -1 generic fatal error
**  @retval -2 ErrorString is undefined
*/
int HttpInspectSnortConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf, char *args, int iGlobal,
                         char *ErrorString, int ErrStrLen)
{
    char        *pcToken;
    static int  s_iGlobal = 0;
    int         iRet;

    /*
    **  Check input variables
    */
    if(ErrorString == NULL)
    {
        return -2;
    }
    
    if(GlobalConf == NULL)
    {
        snprintf(ErrorString, ErrStrLen, 
                "Global configuration variable undefined.");

        return -1;
    }

    if(args == NULL)
    {
        snprintf(ErrorString, ErrStrLen, 
                "No arguments to HttpInspect configuration.");

        return -1;
    }

    /*
    **  Find out what is getting configured
    */
    pcToken = strtok(args, CONF_SEPARATORS);
    if(pcToken == NULL)
    {
        snprintf(ErrorString, ErrStrLen, 
                "No arguments to HttpInspect configuration.");

        return -1;
    }

    /*
    **  Global Configuration Processing
    **  We only process the global configuration once, but always check for
    **  user mistakes, like configuring more than once.  That's why we
    **  still check for the global token even if it's been checked.
    */
    if((s_iGlobal || iGlobal) && !strcmp(pcToken, GLOBAL)) 
    {
        /*
        **  Don't allow user to configure twice
        */
        if(s_iGlobal)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Cannot configure '%s' settings more than once.",
                    GLOBAL);

            return -1;
        }

        /*
        **  Reset the Global configuration
        */
        if(hi_ui_config_reset_global(GlobalConf))
        {
            snprintf(ErrorString, ErrStrLen,
                    "Cannot reset the HttpInspect global configuration.");

            return -1;
        }

        /*
        **  Reset the global server, so if there isn't one specified, we
        **  honor that.
        */
        if(hi_ui_config_reset_server(&GlobalConf->global_server))
        {
            snprintf(ErrorString, ErrStrLen,
                    "Cannot reset the HttpInspect default server configuration.");

            return -1;
        }

        if((iRet = ProcessGlobalConf(GlobalConf, ErrorString, ErrStrLen)))
        {
            return iRet;
        }

        s_iGlobal = 1;

        /*
        **  Let's print out the global config
        */
        PrintGlobalConf(GlobalConf);
    }
    /*
    **  Server Configuration
    */
    else if(!iGlobal && !strcmp(pcToken, SERVER))
    {
        if((iRet = ProcessUniqueServerConf(GlobalConf, 
                                           ErrorString, ErrStrLen)))
        {
            return iRet;
        }
    }
    /*
    **  Invalid configuration keyword
    */
    else
    {
        if(iGlobal)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid configuration token '%s'.  " 
                    "The first configuration must start with a '%s' "
                    "configuration type.", pcToken, GLOBAL);
        }
        else
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid configuration token '%s'.  Must be a '%s' "
                    "configuration.", pcToken, SERVER);
        }

        return -1;
    }

    return 0;
}

/*
**  NAME
**    LogEvents::
*/
/**
**  This is the routine that logs HttpInspect alerts through Snort.
**  
**  Every Session gets looked at for any logged events, and if there are
**  events to be logged then we select the one with the highest priority.
**  
**  We use a generic event structure that we set for each different event
**  structure.  This way we can use the same code for event logging regardless
**  of what type of event strucure we are dealing with.
**  
**  The important things to know about this function is how to work with
**  the event queue.  The number of unique events is contained in the
**  stack_count variable.  So we loop through all the unique events and
**  find which one has the highest priority.  During this loop, we also
**  re-initialize the individual event counts for the next iteration, saving
**  us time in a separate initialization phase.
**  
**  After we've iterated through all the events and found the one with the
**  highest priority, we then log that event through snort.
**  
**  We've mapped the HttpInspect and the Snort alert IDs together, so we
**  can access them directly instead of having a more complex mapping
**  function.  It's the only good way to do this.
**  
**  @param Session          pointer to Session construct
**  @param p                pointer to the Snort packet construct
**  @param iInspectMode     inspection mode to take event queue from
**  
**  @return integer
**  
**  @retval 0 this function only return success
*/
static inline int LogEvents(HI_SESSION *hi_ssn, Packet *p, int iInspectMode)
{
    HI_GEN_EVENTS GenEvents;
    HI_EVENT      *OrigEvent;
    HI_EVENT      *HiEvent = NULL;
    Session       *ssn = NULL;
    u_int32_t     uiMask = 0;
    int           iGenerator;
    int           iStackCnt;
    int           iEvent;
    int           iCtr;

    /*
    **  Set the session ptr, if applicable
    */
    if(p && p->ssnptr)
        ssn = (Session *)p->ssnptr;
    
    if(iInspectMode == HI_SI_CLIENT_MODE)
    {
        GenEvents.stack =       hi_ssn->client.event_list.stack;
        GenEvents.stack_count = &(hi_ssn->client.event_list.stack_count);
        GenEvents.events =      hi_ssn->client.event_list.events;

        iGenerator = GENERATOR_SPP_HTTP_INSPECT_CLIENT;
    }
    else if(iInspectMode == HI_SI_SERVER_MODE)
    {
        /*
        **  We have no server events right now, so we just return.
        */
        return 0;
    }
    else
    {
        GenEvents.stack =       hi_ssn->anom_server.event_list.stack;
        GenEvents.stack_count = &(hi_ssn->anom_server.event_list.stack_count);
        GenEvents.events =      hi_ssn->anom_server.event_list.events;

        iGenerator = GENERATOR_SPP_HTTP_INSPECT_ANOM_SERVER;
    }

    /*
    **  Now starts the generic event processing
    */
    iStackCnt = *(GenEvents.stack_count);

    /*
    **  IMPORTANT::
    **  We have to check the stack count of the event queue before we process
    **  an log.
    */
    if(iStackCnt == 0)
    {
        return 0;
    }

    /*
    **  Cycle through the events and select the event with the highest
    **  priority.
    */
    for(iCtr = 0; iCtr < iStackCnt; iCtr++)
    {
        iEvent = GenEvents.stack[iCtr];
        OrigEvent = &(GenEvents.events[iEvent]);

        /*
        **  Set the event to start off the comparison
        */
        if(!HiEvent)
        {
            HiEvent = OrigEvent;
        }

        /*
        **  This is our "comparison function".  Log the event with the highest
        **  priority.
        */
        if(OrigEvent->event_info->priority < HiEvent->event_info->priority)
        {
            HiEvent = OrigEvent;
        }

        /*
        **  IMPORTANT:
        **    This is how we reset the events in the event queue.
        **    If you miss this step, you can be really screwed.
        */
        OrigEvent->count = 0;
    }

    /*
    **  We use the iEvent+1 because the event IDs between snort and
    **  HttpInspect are mapped off-by-one.  Don't ask why, drink Bud
    **  Dry . . . They're mapped off-by one because in the internal
    **  HttpInspect queue, events are mapped starting at 0.  For some
    **  reason, it appears that the first event can't be zero, so we
    **  use the internal value and add one for snort.
    */
    iEvent = HiEvent->event_info->alert_id + 1;

    uiMask = (u_int32_t)(1 << (iEvent & 31));

    /*
    **  If we've already logged this event for this stream, then
    **  don't log it again.
    */
    if(ssn && (ssn->http_alert_flags & uiMask))
    {
        return 0;
    }

    GenerateSnortEvent(p, iGenerator, iEvent, 1, 0, 1,
            HiEvent->event_info->alert_str);

    /*
    **  Set the http_flag bit so we don't log the event on a reassembled
    **  stream.
    */
    if(ssn)
        ssn->http_alert_flags |= uiMask;

    /*
    **  Reset the event queue stack counter, in the case of pipelined
    **  requests.
    */
    *(GenEvents.stack_count) = 0;

    return 0;
}

static inline int SetSiInput(HI_SI_INPUT *SiInput, Packet *p)
{
    SiInput->sip   = p->iph->ip_src.s_addr;
    SiInput->dip   = p->iph->ip_dst.s_addr;
    SiInput->sport = p->sp;
    SiInput->dport = p->dp;

    /*
    **  We now set the packet direction
    */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        SiInput->pdir = HI_SI_SERVER_MODE;
    }
    else if(p->packet_flags & PKT_FROM_CLIENT)
    {
        SiInput->pdir = HI_SI_CLIENT_MODE;
    }
    else
    {
        SiInput->pdir = HI_SI_NO_MODE;
    }

    return HI_SUCCESS;

}

/*
**  NAME
**    SnortHttpInspect::
*/
/**
**  This function calls the HttpInspect function that processes an HTTP 
**  session.
**
**  We need to instantiate a pointer for the HI_SESSION that HttpInspect 
**  fills in.  Right now stateless processing fills in this session, which 
**  we then normalize, and eventually detect.  We'll have to handle 
**  separately the normalization events, etc.
**  
**  This function is where we can see from the highest level what the
**  HttpInspect flow looks like.
**
**  @param GlobalConf pointer to the global configuration
**  @param p          pointer to the Packet structure
**
**  @return integer
**
**  @retval  0 function successful
**  @retval <0 fatal error
**  @retval >0 non-fatal error
*/
int SnortHttpInspect(HTTPINSPECT_GLOBAL_CONF *GlobalConf, Packet *p)
{
    extern HttpUri UriBufs[URI_COUNT];
    extern int     do_detect;
    extern OptTreeNode *otn_tmp;

    HI_SESSION  *Session;
    HI_SI_INPUT SiInput;
    int iInspectMode = 0;
    int iRet;
    int iCallDetect = 1;
    
    if(!p->iph || !p->tcph)
    {
        return 1;
    }

    /*
    **  Set up the HI_SI_INPUT pointer.  This is what the session_inspection()
    **  routines use to determine client and server traffic.  Plus, this makes
    **  the HttpInspect library very independent from snort.
    */
    SetSiInput(&SiInput, p);

    /*
    **  HTTPINSPECT PACKET FLOW::
    **
    **  Session Inspection Module::
    **    The Session Inspection Module retrieves the appropriate server
    **    configuration for sessions, and takes care of the stateless
    **    vs. stateful processing in order to do this.  Once this module
    **    does it's magic, we're ready for the primetime.
    **
    **  HTTP Inspection Module::
    **    This isn't really a module in HttpInspect, but more of a helper
    **    function that sends the data to the appropriate inspection
    **    routine (client, server, anomalous server detection).
    **
    **  HTTP Normalization Module::
    **    This is where we normalize the data from the HTTP Inspection
    **    Module.  The Normalization module handles what type of normalization
    **    to do (client, server).
    **
    **  HTTP Detection Module::
    **    This isn't being used in the first iteration of HttpInspect, but
    **    all the HTTP detection components of signatures will be.
    **
    **  HTTP Event Output Module::
    **    The Event Ouput Module handles any events that have been logged
    **    in the inspection, normalization, or detection phases.
    */ 
    
    /*
    **  Session Inspection Module::
    */
    if((iRet = hi_si_session_inspection(GlobalConf, &Session, &SiInput, 
                    &iInspectMode)))
    {
        return iRet;
    }
    
    /*
    **  HTTP Inspection Module::
    **
    **  This is where we do the client/server inspection and find the
    **  various HTTP protocol fields.  We then normalize these fields and
    **  call the detection engine.
    **
    **  The reason for the loop is for pipelined requests.  Doing pipelined
    **  requests in this way doesn't require any memory or tracking overhead.
    **  Instead, we just process each request linearly.
    */
    do
    {
        /*
        **  INIT:
        **  We set this equal to zero (again) because of the pipelining
        **  requests.  We don't want to bail before we get to setting the
        **  URI, so we make sure here that this can't happen.
        */
        p->uri_count = 0;
        UriBufs[0].decode_flags = 0;

        if((iRet = hi_mi_mode_inspection(Session, iInspectMode, p->data,
                                         p->dsize)))
        {
            LogEvents(Session,p,iInspectMode);
            return iRet;
        }

        if((iRet = hi_normalization(Session, iInspectMode)))
        {
            LogEvents(Session,p,iInspectMode);
            return iRet;
        }

        /*
        **  Let's setup the pointers for the detection engine, and
        **  then go for it.
        */
        if(iInspectMode == HI_SI_CLIENT_MODE)
        {
            if(!iCallDetect && (Session->client.request.pipeline_req || 
               Session->server_conf->uri_only))
            {
                UriBufs[0].decode_flags |= HTTPURI_PIPELINE_REQ;
            }

            if(Session->client.request.uri_norm)
            {
                UriBufs[0].uri    = Session->client.request.uri_norm;
                UriBufs[0].length = Session->client.request.uri_norm_size;
            }
            else
            {
                UriBufs[0].uri    = Session->client.request.uri;
                UriBufs[0].length = Session->client.request.uri_size;
            }
            
            p->uri_count = 1;
        }
        else if(iInspectMode == HI_SI_SERVER_MODE)
        {
            /*
            **  We set the header length and detect the normal way.
            */
            p->dsize = Session->server.header_size;

            /*
            **  If dsize is 0, we only get here because dsize was set to 0
            **  by the server module by the flow_depth inspection.
            **
            **  We check here to see whether this was a server response
            **  header or not.  If the dsize is 0 then, we know that this
            **  is not the header and don't do any detection.
            */
            if(p->dsize == 0)
            {
                do_detect = 0;
                p->preprocessors = 0;

                p->preprocessors |= PP_PORTSCAN;
                p->preprocessors |= PP_STREAM4;

                return 0;
            }
        }
        else
        {
            /*
            **  We log events before doing detection because every non-HTTP
            **  packet is possible an anomalous server.  So we still want to
            **  go through the regular detection engine, and just log any
            **  alerts here before returning. 
            **
            **  Return normally if this isn't either HTTP client or server
            **  traffic.
            */
            if(Session->anom_server.event_list.stack_count)
                LogEvents(Session, p, iInspectMode);

            return 0;
        }

        /*
        **  If we get here we either had a client or server request/response.
        **  We do the detection here, because we're starting a new paradigm
        **  about protocol decoders.
        **
        **  Protocol decoders are now their own detection engine, since we are
        **  going to be moving protocol field detection from the generic
        **  detection engine into the protocol module.  This idea scales much
        **  better than having all these Packet struct field checks in the
        **  main detection engine for each protocol field.
        */
        Detect(p);
        otn_tmp = NULL;

        /*
        **  Handle event stuff after we do detection.
        **
        **  Here's the reason why:
        **    - since snort can only handle one logged event per packet, 
        **      we only log HttpInspect events if there wasn't one in the
        **      detection engine.  I say that events generated in the
        **      "advanced generic content matching" engine is more 
        **      important than generic events that I can log here.
        */
        LogEvents(Session, p, iInspectMode);

        /*
        **  We set the global detection flag here so that if request pipelines
        **  fail, we don't do any detection.
        */
        do_detect = 0;
        iCallDetect = 0;

    } while(Session->client.request.pipeline_req);

    return 0;
}

    
    





