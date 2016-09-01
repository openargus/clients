/* $Id: hi_client.h,v 1.2 2003/12/03 15:22:23 chris_reid Exp $ */

#ifndef __HI_CLIENT_H__
#define __HI_CLIENT_H__


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>

#include "hi_include.h"
#include "hi_eo.h"
#include "hi_eo_events.h"

typedef struct s_HI_CLIENT_REQ
{
    /*
    u_char *method;
    int  method_size;
    */

    u_char *uri;
    u_char *uri_norm;
    u_int  uri_size;
    u_int uri_norm_size;

    /*
    u_char *param;
    u_int  param_size;
    u_int  param_norm;
    */

    /*
    u_char *ver;
    u_int  ver_size;

    u_char *hdr;
    u_int  hdr_size;

    u_char *payload;
    u_int  payload_size;
    */

    u_char *pipeline_req;

}  HI_CLIENT_REQ;

typedef struct s_HI_CLIENT
{
    HI_CLIENT_REQ request;
    int (*state)(void *, unsigned char, int);
    HI_CLIENT_EVENTS event_list;

}  HI_CLIENT;

int hi_client_inspection(void *Session, unsigned char *data, int dsize);
int hi_client_init(HTTPINSPECT_GLOBAL_CONF *GlobalConf);

#endif 
