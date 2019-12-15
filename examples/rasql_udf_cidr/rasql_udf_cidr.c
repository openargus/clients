/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 *
 * rasql_udf_str - a library of functions to work with ip Cidr Addresses.
 *
 */
#include <unistd.h>

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <syslog.h>

#include <mysql.h>
#include <server/m_ctype.h>

#if defined(PACKAGE_VERSION)
#undef PACKAGE_VERSION
#endif
#if defined(PACKAGE_BUGREPORT)
#undef PACKAGE_BUGREPORT
#endif
#if defined(PACKAGE_NAME)
#undef PACKAGE_NAME
#endif
#if defined(PACKAGE_STRING)
#undef PACKAGE_STRING
#endif
#if defined(PACKAGE_TARNAME)
#undef PACKAGE_TARNAME
#endif

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <argus_compat.h>
#include <argus_util.h>

#define DLLEXP
#define ATTRIBUTE_UNUSED 

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#endif

#ifdef HAVE_DLOPEN

#define LIBVERSION ("rasql_udf_str version " PACKAGE_VERSION)
#define ROT_OFFSET 13

#define ARGCOUNTCHECK(typestr)   \
   if (args->arg_count != 1) { \
      snprintf(message, MYSQL_ERRMSG_SIZE, "wrong argument count: %s requires one " typestr " argument, got %d arguments", funcname, args->arg_count); \
      return 1; \
   }


#define ARGTYPECHECK(arg, type, typestr)   \
   if (arg != type) { \
      snprintf(message, MYSQL_ERRMSG_SIZE, "wrong argument type: %s requires one " typestr " argument. Expected type %d, got type %d.", funcname, type, arg); \
      return 1; \
   }

#define STRARGCHECK ARGTYPECHECK(args->arg_type[0], STRING_RESULT, "string")
#define INTARGCHECK ARGTYPECHECK(args->arg_type[0], INT_RESULT, "integer")

struct ArgusCIDRAddr *MySqlRaParseCIDRAddr (char *, struct ArgusCIDRAddr *);

/******************************************************************************
** function declarations
******************************************************************************/
#ifdef   __cplusplus
extern "C" {
#endif

#define DECLARE_UDF_INIT_DEINIT(name_id) \
   DLLEXP my_bool name_id ## _init(UDF_INIT *, UDF_ARGS *, char *); \
   DLLEXP void name_id ## _deinit(UDF_INIT *);
#define DECLARE_STRING_UDF(name_id) \
   DECLARE_UDF_INIT_DEINIT(name_id) \
   DLLEXP char *name_id(UDF_INIT *, UDF_ARGS *, char *, unsigned long *, char *, char *);
#define DECLARE_INTEGER_UDF(name_id) \
   DECLARE_UDF_INIT_DEINIT(name_id) \
   DLLEXP long long name_id(UDF_INIT *, UDF_ARGS *, char *, char *);

DECLARE_STRING_UDF(rasql_udf_cidr_info)
DECLARE_STRING_UDF(str_numtowords)
DECLARE_INTEGER_UDF(rasql_compareCidrtoAddr)

#ifdef   __cplusplus
}
#endif

/******************************************************************************
** function definitions
******************************************************************************/

/******************************************************************************
** purpose:   called once for each SQL statement which invokes rasql_udf_cidr_info_init();
**               checks arguments, sets restrictions, allocates memory that
**               will be used during the main rasql_udf_cidr_info_init() function
** receives:   pointer to UDF_INIT struct which is to be shared with all
**               other functions (rasql_udf_cidr_info_init() and rasql_udf_cidr_info_init_deinit()) -
**               the components of this struct are described in the MySQL manual;
**               pointer to UDF_ARGS struct which contains information about
**               the number, size, and type of args the query will be providing
**               to each invocation of rasql_udf_cidr_info_init(); pointer to a char
**               array of size MYSQL_ERRMSG_SIZE in which an error message
**               can be stored if necessary
** returns:   1 => failure; 0 => successful initialization
******************************************************************************/
my_bool
rasql_udf_cidr_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
   my_bool retn = 0;

   if (args->arg_count != 0) {
      strncpy(message, "No arguments allowed (udf: rasql_udf_cidr_info)", MYSQL_ERRMSG_SIZE);
      retn = 1;
   }

   initid->maybe_null = 0;
   initid->max_length = (sizeof LIBVERSION) - 1;
   initid->const_item = 1;
   return retn;
}

/******************************************************************************
** purpose:   deallocate memory allocated by rasql_udf_cidr_info_init();
**               this function is called once for each query which invokes
**               rasql_udf_cidr_info(), it is called after all of the calls to
**               rasql_udf_cidr_info() are done
** receives:   pointer to UDF_INIT struct (the same which was used by
**               rasql_udf_cidr_info_init() and rasql_udf_cidr_info())
** returns:   nothing
******************************************************************************/
void 
rasql_udf_cidr_info_deinit(UDF_INIT *initid ATTRIBUTE_UNUSED)
{
}

/******************************************************************************
** purpose:   obtain information about the currently installed version
**               of rasql_udf_str.
** receives:   pointer to UDF_INIT struct which contains pre-allocated memory
**               in which work can be done; pointer to UDF_ARGS struct which
**               contains the functions arguments and data about them; pointer
**               to mem which can be set to 1 if the result is NULL; pointer
**               to mem which can be set to 1 if the calculation resulted in an
**               error
** returns:   the library version number
******************************************************************************/
char *
rasql_udf_cidr_info(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *res_length, char *null_value, char *error)
{
   strcpy(result, LIBVERSION);
   *res_length = (sizeof LIBVERSION) - 1;
   return result;
}



/******************************************************************************
** purpose:   called once for each SQL statement which invokes str_numtowords();
**               checks arguments, sets restrictions, allocates memory that
**               will be used during the main str_numtowords() function
** receives:   pointer to UDF_INIT struct which is to be shared with all
**               other functions (str_numtowords() and str_numtowords_deinit()) -
**               the components of this struct are described in the MySQL manual;
**               pointer to UDF_ARGS struct which contains information about
**               the number, size, and type of args the query will be providing
**               to each invocation of str_numtowords(); pointer to a char
**               array of size MYSQL_ERRMSG_SIZE in which an error message
**               can be stored if necessary
** returns:   1 => failure; 0 => successful initialization
******************************************************************************/
my_bool
str_numtowords_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
   static const char funcname[] = "str_numtowords";
   my_bool retn = 0;

   /* make sure user has provided exactly one integer argument */
   ARGCOUNTCHECK("integer");
   INTARGCHECK;

   initid->maybe_null=1;
   return retn;
}

/******************************************************************************
** purpose:   deallocate memory allocated by str_numtowords_init(); this func
**               is called once for each query which invokes str_numtowords(),
**               it is called after all of the calls to str_numtowords() are done
** receives:   pointer to UDF_INIT struct (the same which was used by
**               str_numtowords_init() and str_numtowords())
** returns:   nothing
******************************************************************************/
void str_numtowords_deinit(UDF_INIT *initid)
{
}

#define STR_LENGTH(str) ((sizeof (str)) -1)
#define STR_COMMA_LENGTH(str_lit) str_lit, STR_LENGTH(str_lit)

/******************************************************************************
** purpose:   convert numbers written in arabic digits to an english word.
**               Works for positive and negative numbers up to 9 digits long.
** receives:   pointer to UDF_INIT struct which contains pre-allocated memory
**               in which work can be done; pointer to UDF_ARGS struct which
**               contains the functions arguments and data about them; pointer
**               to mem which can be set to 1 if the result is NULL; pointer
**               to mem which can be set to 1 if the calculation resulted in an
**               error
** returns:   the string spelling the given number in English
******************************************************************************/
char *
str_numtowords(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *res_length, char *null_value, char *error)
{
   char *retn = "It's working";

   *res_length = strlen(retn);
   result = retn;
   return result;
}

/******************************************************************************
** purpose:   called once for each SQL statement which invokes str_numtowords();
**               checks arguments, sets restrictions, allocates memory that
**               will be used during the main str_numtowords() function
** receives:   pointer to UDF_INIT struct which is to be shared with all
**               other functions (str_numtowords() and str_numtowords_deinit()) -
**               the components of this struct are described in the MySQL manual;
**               pointer to UDF_ARGS struct which contains information about
**               the number, size, and type of args the query will be providing
**               to each invocation of str_numtowords(); pointer to a char
**               array of size MYSQL_ERRMSG_SIZE in which an error message
**               can be stored if necessary
** returns:   1 => failure; 0 => successful initialization
******************************************************************************/

my_bool
rasql_compareCidrtoAddr_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
   static const char funcname[] = "rasql_compareCidrtoAddr";
   my_bool retn = 1;

   if (args->arg_count == 2) {
      if ((args->arg_type[0] == STRING_RESULT) && (args->arg_type[1] == STRING_RESULT)) {
         retn = 0;
      }
   }
   initid->maybe_null=0;
   return retn;
}

/******************************************************************************
** purpose:   deallocate memory allocated by str_numtowords_init(); this func
**               is called once for each query which invokes str_numtowords(),
**               it is called after all of the calls to str_numtowords() are done
** receives:   pointer to UDF_INIT struct (the same which was used by
**               str_numtowords_init() and str_numtowords())
** returns:   nothing
******************************************************************************/

void rasql_compareCidrtoAddr_deinit(UDF_INIT *initid)
{
}

#define STR_LENGTH(str) ((sizeof (str)) -1)
#define STR_COMMA_LENGTH(str_lit) str_lit, STR_LENGTH(str_lit)

/******************************************************************************
** purpose:   convert numbers written in arabic digits to an english word.
**               Works for positive and negative numbers up to 9 digits long.
** receives:   pointer to UDF_INIT struct which contains pre-allocated memory
**               in which work can be done; pointer to UDF_ARGS struct which
**               contains the functions arguments and data about them; pointer
**               to mem which can be set to 1 if the result is NULL; pointer
**               to mem which can be set to 1 if the calculation resulted in an
**               error
** returns:   the string spelling the given number in English
******************************************************************************/
long long 
rasql_compareCidrtoAddr(UDF_INIT *initid, UDF_ARGS *args, char *null_value, char *error)
{
   char s1buf[128], s2buf[128];
   struct ArgusCIDRAddr caddr1, caddr2;
   struct ArgusCIDRAddr *cptr1 = NULL, *cptr2 = NULL;
   long long retn = 0;

   bcopy(args->args[0], s1buf, args->lengths[0]); s1buf[args->lengths[0]] = '\0';
   bcopy(args->args[1], s2buf, args->lengths[1]); s2buf[args->lengths[1]] = '\0';

   cptr1 = MySqlRaParseCIDRAddr (s1buf, &caddr1);
   cptr2 = MySqlRaParseCIDRAddr (s2buf, &caddr2);

   if (cptr1 && cptr2) {
      if (cptr1->type == cptr2->type) {
         switch (cptr1->type) {
            case AF_INET: {
               unsigned int m1 = cptr1->mask[0];
               unsigned int s1 = cptr1->addr[0] & m1;
               unsigned int s2 = cptr2->addr[0] & m1;

               if (s1 == s2)
                  retn = 1;
               break;
            }

            case AF_INET6:
               break;
         }
      }
   }
   return retn;
}

/*
   There are two types of addresses to parse, IPv4 and IPv6
   addresses.  An address is in the form:
     dd[.:][:][dd]/n

   where n is the number significant bits in the address.
*/
int ArgusNumTokens (char *, char);
   
int
ArgusNumTokens (char *str, char tok)
{
   int retn = 0;
   if (str != NULL) {
      while ((str = strchr(str, tok)) != NULL) {
         retn++;
         str++;
      }
   }
   return (retn);
}

struct ArgusCIDRAddr *
MySqlRaParseCIDRAddr (char *addr, struct ArgusCIDRAddr *cidr)
{
   char *ptr = NULL, *mask = NULL, strbuf[128], *str = strbuf;
   struct ArgusCIDRAddr *retn = NULL;

   memset(cidr, 0, sizeof(*cidr));
   snprintf (str, sizeof(strbuf), "%s", addr);

   if ((ptr = strchr(str, '!')) != NULL) {
      str = ptr + 1;
   }

   if ((mask = strchr (str, '/')) != NULL) {
      *mask++ = '\0';
      cidr->masklen = strtol((const char *)mask, (char **)&ptr, 10);
      if (ptr == mask) {
         return (NULL);
      }
   }

   if ((ptr = strchr (str, ':')) != NULL) {
      cidr->type = AF_INET6;
      if (cidr->masklen == 0) {
         cidr->masklen = 128;
      }
   } else if ((ptr = strchr (str, '.')) != NULL) {
      if (cidr->masklen == 0) {
         cidr->masklen = 32;
      }
      if (strlen (str) > 1) {
         cidr->type = AF_INET;
      } else
         return (NULL);
   }
  
   if (!(cidr->type))
      cidr->type = (cidr->masklen > 32) ? AF_INET6 : AF_INET;
   
   switch (cidr->type) {
      case AF_INET: {
         int i, len = sizeof(struct in_addr);
 
         cidr->len = len;

         for (i = 0; (i < len) && str; i++) {
            long int tval = strtol(str, (char **)&ptr, 10);
            if (ptr != NULL) {
               if (strlen(ptr) > 0) {
                  if (*ptr++ != '.') {
                     return(NULL);
                  }
               } else
                  ptr = NULL;

               cidr->addr[0] |= (tval << ((len - (i + 1)) * 8));
            }
            str = ptr;
         }

         if ((cidr->masklen == 0) && (cidr->addr[0] != 0))
            cidr->masklen = 32;

         if (cidr->masklen > 0)
            cidr->mask[0] = 0xFFFFFFFF << (32 - cidr->masklen);

         retn = cidr;
         break;
      }

      case AF_INET6: {
         unsigned short *val = (unsigned short *)&cidr->addr;
         int ind = 0, len = sizeof(cidr->addr)/sizeof(unsigned short);
         int fsecnum = 8, lsecnum = 0, rsecnum = 0, i, masklen;
         char *sstr = NULL, *ipv4addr = NULL;

         cidr->len = sizeof(cidr->addr);

         if ((sstr = strstr(str, "::")) != NULL) {
            *sstr++ = '\0';
            *sstr++ = '\0';
            if (strlen(str)) {
               if (!(strncmp("fe80:", str, 5)))   // test if scope id is embedded in the address and remove
                  str[4] = '\0';
               fsecnum = ArgusNumTokens(str,  ':') + 1;
            }
            if (strlen(sstr))
               lsecnum = ArgusNumTokens(sstr, ':') + 1;
         } else
            sstr = str;

         if (cidr->masklen == 0)
            cidr->masklen = 128;

         if (strchr (sstr, '.')) {
            lsecnum += (lsecnum > 0) ? 1 : 2;
            if ((ipv4addr = strrchr(sstr, ':')) == NULL) {
               ipv4addr = sstr;
               sstr = NULL;
            } else {
               *ipv4addr++ = '\0';
            }
         }

         if (fsecnum + lsecnum) {
            rsecnum = 8 - (fsecnum + lsecnum);
            if (fsecnum) {
               while (str && *str && (ind++ < len)) {
                  *val++ = htons(strtol(str, (char **)&ptr, 16));

                  if (ptr != NULL) {
                     if (strlen(ptr) > 0) {
                        if (*ptr++ != ':') {
                           return(NULL);
                        }
                     } else
                        ptr = NULL;
                  }
                  str = ptr;
               }
            }

            for (i = 0; i < rsecnum; i++)
               *val++ = 0;
            if (lsecnum) {
               if ((str = sstr) != NULL) {
                  while (str && (ind++ < len)) {
                     *val++ = htons(strtol(str, (char **)&ptr, 16));

                     if (ptr != NULL) {
                        if (strlen(ptr) > 0) {
                           if (*ptr++ != ':') {
                              return(NULL);
                           }
                        } else
                           ptr = NULL;
                     }
                     str = ptr;
                  }
               }
            }

            if (ipv4addr) {
               unsigned char *cval = (unsigned char *)&cidr->addr[3];
               int ind = 0, len = sizeof(struct in_addr);
 
               while (ipv4addr && (ind++ < len)) {
                  *cval++ = strtol(ipv4addr, (char **)&ptr, 10);
                  if (ptr != NULL) {
                     if (strlen(ptr) > 0) {
                        if (*ptr++ != '.') {
                           return(NULL);
                        }
                     } else
                        ptr = NULL;
                  }
                  ipv4addr = ptr;
               }
               cidr->masklen = 128;
            }
         }

         for (i = 0; i < 4; i++) cidr->mask[i] = 0;

         if ((masklen = cidr->masklen) > 0) {
            unsigned int *mask = &cidr->mask[0];

            while (masklen) {
               if (masklen > 32) {
                  *mask++ = 0xFFFFFFFF;
                  masklen -= 32;
               } else {
                  *mask = htonl(0xFFFFFFFF << (32 - masklen));
                  masklen = 0;
               }
            }
         }
         retn = cidr;
         break;
      }

      default:
         break;
   }
   return (retn);
}
#endif
