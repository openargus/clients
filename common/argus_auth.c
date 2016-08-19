/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Modified by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/common/argus_auth.c#29 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */


#ifndef ArgusAuth
#define ArgusAuth
#endif

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <stdlib.h>
#include <unistd.h>

#include <errno.h>

#include <argus_compat.h>

#include <netinet/in.h>
#include <string.h>

#include <syslog.h>

#include <ctype.h>
#include <assert.h>
#include <netdb.h>

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#endif /* ARGUS_SASL */

#include <argus_int.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_parser.h>
#include <argus_client.h>
#include <argus_filter.h>

extern struct ArgusParserStruct *ArgusParser;
extern void ArgusLog (int, char *, ...);

int ArgusInitializeAuthentication (struct ArgusInput *);
int ArgusAuthenticate (struct ArgusInput *);
int RaSaslNegotiate(struct ArgusInput *input);

int iptostring(const struct sockaddr *, socklen_t, char *, unsigned);

#ifdef ARGUS_SASL

extern int ArgusMaxSsf;
extern int ArgusMinSsf;

int RaGetRealm(void *context, int, const char **, const char **);
int RaSimple(void *context, int, const char **, unsigned *);
int RaGetSecret(sasl_conn_t *, void *context, int, sasl_secret_t **);
int ArgusSaslGetPath(void *context __attribute__((unused)), char **);
int ArgusSaslLog (void *context __attribute__((unused)), int, const char *);

#define PLUGINDIR "/usr/lib/sasl2"
char *searchpath = NULL;

int
ArgusSaslGetPath(void *context __attribute__((unused)), char ** path)
{
  if (! path)
    return SASL_BADPARAM;
  if (searchpath)
    *path = searchpath;
   else
    *path = PLUGINDIR;

#ifdef ARGUSDEBUG
  ArgusDebug(2, "SASL path %s", *path);
#endif

  return SASL_OK;
}

int
ArgusSaslLog (void *context __attribute__((unused)), int priority, const char *message)
{
#ifdef ARGUSDEBUG
  const char *label;

  if (! message)
    return SASL_BADPARAM;

  switch (priority) {
     case SASL_LOG_ERR:  label = "Error"; break;
     case SASL_LOG_NOTE: label = "Info"; break;
     default:            label = "Other"; break;
  }

  ArgusDebug(1, "ArgusSaslLog %s: %s", label, message);
#endif

  return SASL_OK;
}


unsigned int RaGetSaslString (int, char *, int);
int RaSendSaslString (int, const char *, int, int);
void RaChop (char *);

/* RaCallBacks we support */

typedef int (*funcptr)();



sasl_callback_t RaCallBacks[] = {
  { SASL_CB_GETREALM, (funcptr)&RaGetRealm,  NULL },
  { SASL_CB_USER,     (funcptr)&RaSimple,    NULL },
  { SASL_CB_AUTHNAME, (funcptr)&RaSimple,    NULL },
  { SASL_CB_PASS,     (funcptr)&RaGetSecret, NULL },
  { SASL_CB_GETPATH,  (funcptr)&ArgusSaslGetPath, NULL },
  { SASL_CB_LIST_END, NULL, NULL }
};

char *RaSaslMech = NULL;

#endif /* ARGUS_SASL */


int
ArgusInitializeAuthentication (struct ArgusInput *input)
{
   int retn = 1;

#ifdef ARGUS_SASL
#define SASL_SEC_MASK   0x0fff

   struct sockaddr_storage localaddr, remoteaddr;
   char *remotehostname = NULL;
   char remoteip[60], localip[60];
   sasl_security_properties_t secprops;
   int fd = input->fd;
   socklen_t salen;

   if ((retn = sasl_client_init(RaCallBacks)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() sasl_client_init %d", retn);

    /* set the IP addresses */
   salen =sizeof(struct sockaddr_storage);
   if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) != 0)
      return SASL_FAIL;
   if(iptostring((struct sockaddr *)&remoteaddr, salen, remoteip, 60) != 0)
      return SASL_FAIL;

   salen =sizeof(struct sockaddr_storage);
   if (getsockname(fd, (struct sockaddr *)&localaddr, &salen)!=0)
      return SASL_FAIL;
   if(iptostring((struct sockaddr *)&localaddr, salen, localip, 60) != 0)
      return SASL_FAIL;

   /* Require proxying if we have an "interesting" userid (authzid) */

   if ((retn = sasl_client_new("argus", input->hostname, localip, remoteip, RaCallBacks, SASL_SUCCESS_DATA, &input->sasl_conn)) != SASL_OK)
       ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() sasl_client_new %s %d", remotehostname, retn);
      
      /* set external properties here
      sasl_setprop(input->sasl_conn, SASL_SSF_EXTERNAL, &extprops); */

     /* set required security properties here */

      bzero((char *)&secprops, sizeof(secprops));
      secprops.maxbufsize = 0x10000;
      secprops.min_ssf = ArgusMinSsf;
      secprops.max_ssf = ArgusMaxSsf;

      if (sasl_setprop(input->sasl_conn, SASL_SEC_PROPS, &secprops) != SASL_OK)
         ArgusLog (LOG_ERR, "sasl_setprop %s", sasl_errdetail(input->sasl_conn));
/*      
      salen = sizeof(localaddr);
      if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) < 0)
         perror("getsockname");

      salen = sizeof(remoteaddr); 
      if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) < 0)
         perror("getpeername");

      if ((retn = sasl_setprop(input->sasl_conn, SASL_IP_LOCAL, &localaddr)) != SASL_OK)
         ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() error setting localaddr %d", retn);

      if ((retn = sasl_setprop(input->sasl_conn, SASL_IP_REMOTE, &remoteaddr)) != SASL_OK)
         ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() error setting remoteaddr %d", retn);
*/
      retn = 1;

#else
   ArgusLog (LOG_ERR, "Source requesting unsupported authentication");

#endif /* ARGUS_SASL */

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusInitializeAuthentication () returning %d\n", retn);
#endif

   return (retn);
}


int
ArgusAuthenticate (struct ArgusInput *input)
{
   int retn = 0;
   char *user = NULL, *pass = NULL;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&ArgusParser->lock);
#endif

   if (input->user) {
      user = ArgusParser->ustr;
      ArgusParser->ustr = input->user;
   }

   if (input->pass) {
      pass = ArgusParser->pstr;
      ArgusParser->pstr = input->pass;
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&ArgusParser->lock);
#endif
   
   if (ArgusInitializeAuthentication(input)) {
#ifdef ARGUS_SASL
      int fd = input->fd;

      if ((input->in = fd) < 0)
         ArgusLog (LOG_ERR, "ArgusAuthenticate(0x%x) in fd not set");

      if ((input->out = fd) < 0)
         ArgusLog (LOG_ERR, "ArgusAuthenticate(0x%x) out fd not set");

      if ((retn = RaSaslNegotiate(input)) == SASL_OK)
         retn = 1;
      else
         retn = 0;
#endif /* ARGUS_SASL */
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&ArgusParser->lock);
#endif

   if (user != NULL) ArgusParser->ustr = user;
   if (pass != NULL) ArgusParser->pstr = pass;

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&ArgusParser->lock);
#endif


#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusAuthenticate (0x%x) returning %d\n", input, retn);
#endif

   return (retn);
}


#ifdef ARGUS_SASL

void RaChop (char *s)          /* remove \r\n at end of the line */
{
   char *p;

   assert(s);

   p = s + strlen(s) - 1;
   if (p[0] == '\n')
      *p-- = '\0';

   if (p >= s && p[0] == '\r')
      *p-- = '\0';
}

int
RaGetRealm(void *context __attribute__((unused)), int id,
           const char **availrealms, const char **result)
{
   static char buf[1024];
   char *ptr;

   if (id != SASL_CB_GETREALM)
      return SASL_BADPARAM;

   if (!result)
      return SASL_BADPARAM;

   printf("please choose a realm (available:");
   while (*availrealms) {
      printf(" %s", *availrealms);
      availrealms++;
   }
   printf("): ");

   if ((ptr = fgets(buf, sizeof buf, stdin)) != NULL) {
      RaChop(buf);
      *result = buf;
   }
  
   return SASL_OK;
}

char RaSimpleBuf[1024];

int
RaSimple(void *context __attribute__((unused)), int id, const char **result, unsigned *len)
{
   char *ptr = NULL;

   if (! result)
      return SASL_BADPARAM;

   switch (id) {
      case SASL_CB_USER:
         if (ArgusParser->ustr == NULL) {
            printf("Username: ");
            ptr = fgets(RaSimpleBuf, sizeof RaSimpleBuf, stdin);

         } else {
            if ((ptr = strchr(ArgusParser->ustr, '/')) != NULL)
                *ptr = '\0';
          
            sprintf (RaSimpleBuf, "%s", ArgusParser->ustr);
            if (ptr)
               *ptr = '/';
#ifdef ARGUSDEBUG
            ArgusDebug (4, "RaSimple SASL_CB_USER is %s", RaSimpleBuf);
#endif
         }
         break;

      case SASL_CB_AUTHNAME:
         if (ArgusParser->ustr != NULL) {
            if ((ptr = strchr(ArgusParser->ustr, '/')) != NULL) {
               ptr++;
            } else {
               ptr = ArgusParser->ustr;
            }
         }

         if (ptr == NULL) {
            printf("Authname: ");
            ptr = fgets(RaSimpleBuf, sizeof RaSimpleBuf, stdin);
         } else 
            sprintf (RaSimpleBuf, "%s", ptr);
#ifdef ARGUSDEBUG
         ArgusDebug (4, "RaSimple SASL_CB_AUTHNAME is %s", RaSimpleBuf);
#endif
         break;

      default:
         return SASL_BADPARAM;
   }

   RaChop(RaSimpleBuf);
   *result = RaSimpleBuf;

   if (len)
      *len = strlen(RaSimpleBuf);
  
   return SASL_OK;
}

#ifndef HAVE_GETPASSPHRASE
char * getpassphrase(const char *);

char *
getpassphrase(const char *prompt)
{
  return getpass(prompt);
}
#endif /* ! HAVE_GETPASSPHRASE */

int
RaGetSecret(sasl_conn_t *conn, void *context __attribute__((unused)),
            int id, sasl_secret_t **psecret)
{
   static sasl_secret_t *x = NULL;
   char *password;
   size_t len;

   if (! conn || ! psecret || id != SASL_CB_PASS)
      return SASL_BADPARAM;

   if (ArgusParser->pstr !=  NULL)
      password = ArgusParser->pstr;
   else
      password = getpassphrase("Password: ");

   if (! password)
      return SASL_FAIL;

   len = strlen(password);

   if ((x = (sasl_secret_t *) malloc(sizeof(sasl_secret_t) + len)) == NULL)
      ArgusLog (LOG_ERR, "RaGetSecret: malloc(%d) error %s\n",  (sizeof(sasl_secret_t) + len));
  
   if (!x) {
      memset(password, 0, len);
      return SASL_NOMEM;
   }

   x->len = len;
   strcpy((char *) x->data, password);

   *psecret = x;
   return SASL_OK;
}


int
RaSaslNegotiate(struct ArgusInput *input)
{
   char buf[8192], mechs[1024];
   const char *chosenmech = NULL;
   const char *data = NULL;
   unsigned int len = 0;
   int in, out, retn = 0;
   sasl_conn_t *conn;

   conn = input->sasl_conn;
   in  = input->in;
   out = input->out;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSaslNegotiate(0x%x, 0x%x, 0x%x) receiving capability list... ", in, out, conn);
#endif

   bzero(buf, sizeof(buf));

   if ((len = RaGetSaslString(in, buf, sizeof(buf))) == 0)
      ArgusLog (LOG_ERR, "RaSaslNegotiate: RaGetSaslString(0x%x, 0x%x, %d) error %s\n", in, buf, sizeof(buf), strerror(errno));

   strcpy(mechs, buf);

   if (RaSaslMech) {
   /* make sure that 'RaSaslMech' appears in 'buf' */
      if (!strstr(mechs, RaSaslMech)) {
         printf("server doesn't offer mandatory mech '%s'\n", RaSaslMech);
         RaSendSaslString(out, NULL, 0, SASL_NOMECH);
         return SASL_NOMECH;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSaslNegotiate(0x%x, 0x%x, 0x%x) calling sasl_client_start()", in, out, conn);
#endif

   len = 0; data = "";

   if (RaSaslMech)
      strcpy(mechs, RaSaslMech);

   retn = sasl_client_start(conn, mechs, NULL, &data, &len, &chosenmech);

   if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
      RaSendSaslString(out, NULL, 0, retn);
      ArgusLog (LOG_ERR, "RaSaslNegotiate: error starting SASL negotiation %s", sasl_errdetail(conn));
   }
   
   if (chosenmech != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaSaslNegotiate: using mechanism %s\n", chosenmech);
#endif
      strcpy(buf, chosenmech);
      RaSendSaslString(out, buf, strlen(buf), SASL_OK);
      if (data) {
         RaSendSaslString(out, "Y", 1, SASL_OK);
         RaSendSaslString(out, data, len, SASL_OK);
      } else {
         RaSendSaslString(out, "N", 1, SASL_OK);
      }

      while (retn == SASL_CONTINUE) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "waiting for server reply...\n");
#endif
         len = RaGetSaslString(in, buf, sizeof(buf));
         retn = sasl_client_step(conn, buf, len, NULL, &data, &len);

         if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
            RaSendSaslString(out, NULL, 0, retn);
            ArgusLog (LOG_ERR, "RaSaslNegotiate: sasl_client_step returned %s", sasl_errdetail(conn));
         }

         if (data) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "sending response length %d...\n", len);
#endif
            RaSendSaslString(out, data, len, SASL_CONTINUE);
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "sending null response...\n");
#endif
            RaSendSaslString(out, "", 0, SASL_CONTINUE);
         }
      }

      if (retn == SASL_OK)
         len = RaGetSaslString(in, buf, sizeof(buf));

   } else  {
      ArgusLog (LOG_ERR, "SASL negotiation: no mechanisms");
      retn = SASL_NOMECH;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSaslNegotiate returning %s\n", (retn == SASL_OK) ? "SASL_OK" : "SASL_ERROR");
#endif

   return retn;
}


/* send/recv library for IMAP4 style literals. */

int
RaSendSaslString (int fd, const char *s, int l, int mode)
{
   char *buf = NULL, *ptr = NULL;
   unsigned int al, len;
   int result, tsize;

   switch (mode) {
      case SASL_OK:
      case SASL_CONTINUE: {
         ptr = "C: ";
         tsize = 3;
         break;
      }
      default: {
         ptr = "N: ";
         tsize = 3;
         break;
      }
   }

   while ((result = write(fd, ptr, tsize)) != tsize) {
      if (result >= 0) {
         ptr += result;
         tsize -= result;
      } else {
         if (errno != EAGAIN)
            ArgusLog (LOG_ERR, "write: error %s", strerror(errno));
      }
   }

   if (l > 0) {
      al = (((l / 3) + 1) * 4) + 1;
      if ((buf = malloc(al)) == NULL)
         ArgusLog (LOG_ERR, "malloc: error %s", strerror(errno));

      result = sasl_encode64(s, l, buf, al, &len);
      if (result == SASL_OK) {
         ptr = buf;
         tsize = len;
         while ((result = write(fd, ptr, tsize)) != tsize) {
            if (result >= 0) {
               ptr += result;
               tsize -= result;
            } else {
               if (errno != EAGAIN)
                  ArgusLog (LOG_ERR, "write: error %s", strerror(errno));
            }
         }
      }
      free(buf);
   }

   ptr = "\n";
   tsize = 1;
   while ((result = write(fd, ptr, tsize)) != tsize) {
      if (result >= 0) {
         ptr += result;
         tsize -= result;
      } else {
         if (errno != EAGAIN)
            ArgusLog (LOG_ERR, "write: error %s", strerror(errno));
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaSendSaslString(%d, 0x%x, %d) %s", fd, s, l, s);
#endif

   return len;
}

unsigned int
RaGetSaslString (int fd, char *buf, int buflen)
{
   unsigned int len;
   char *s = buf, c;
   int result, i = 0;

   while (buflen > 1) {
      if ((i = read(fd, &c, 1)) == 1) {
         *s++ = c;
         buflen--;
         if (c == '\n') {
            break;
         }
      }
   }
   if (buflen > 0)
      *s = '\0';

   switch (*buf) {
      case 'S': {
         if (strncmp(buf, "S: ", 3) != 0)
            ArgusLog (LOG_ERR, "RaGetSaslString: format error %s", buf);
         result = SASL_OK;
         s = buf + 3;
         break;
      }
      case 'E': {
         if (sscanf(buf, "E: [%d]", &result) != 1) 
            ArgusLog (LOG_ERR, "RaGetSaslString: format error %s", buf);
         
         if ((s = strchr(buf, ']')) == NULL)
            ArgusLog (LOG_ERR, "RaGetSaslString: format error %s", buf);
         s++;
         break;
      }

      case 'D': {
         if (strncmp(buf, "D: ", 3) != 0)
            ArgusLog (LOG_ERR, "RaGetSaslString: format error %s", buf);

         s = NULL;
         len = 0;
         break;
      }

      default:
         ArgusLog (LOG_ERR, "RaGetSaslString: format error %s", buf);
         break;
   }

   buf[strlen(buf) - 1] = '\0';

   if (s != NULL) {
      i = sasl_decode64(s, (unsigned) strlen(s), buf, buflen, &len);

      if (i != SASL_OK)
         ArgusLog (LOG_ERR, "RaGetSaslString: sasl_decode64 error");

      switch (result) {
         case SASL_OK:
            break;

         default:
            ArgusLog (LOG_ERR, "sasl %s\n", buf);
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaGetSaslString(0x%x, 0x%x, %d) %s", fd, buf, buflen, buf);
#endif
   return len;
}

#endif /* ARGUS_SASL */

int
iptostring(const struct sockaddr *addr, socklen_t addrlen, char *out, unsigned outlen)
{
    char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
    int niflags;

    if(!addr || !out) {
        errno = EINVAL;
        return -1;
    }

    niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#ifdef NI_WITHSCOPEID
    if (addr->sa_family == AF_INET6)
        niflags |= NI_WITHSCOPEID;
#endif
    if (getnameinfo(addr, addrlen, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf), niflags) != 0) {
        errno = EINVAL;
        return -1;
    }

    if(outlen < strlen(hbuf) + strlen(pbuf) + 2) {
        errno = ENOMEM;
        return -1;
    }

    snprintf(out, outlen, "%s;%s", hbuf, pbuf);

    return 0;
}

