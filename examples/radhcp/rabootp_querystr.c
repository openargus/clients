#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rabootp_querystr.h"

static int
__parse_subtoken(const struct QueryOptsStruct * const qopts,
                 size_t nqopts, char *token, char *parsed[])
{
   char *str2, *subtoken;
   char *saveptr2;
   int opt = -1;
   int i;

   for (str2 = token; ; str2 = NULL) {
       subtoken = strtok_r(str2, "=", &saveptr2);
       if (subtoken == NULL)
           break;

       if (opt < 0) {
          for (i = 0; opt < 0 && i < nqopts; i++) {
             if (strcmp(subtoken, qopts[i].lhs) == 0) {
                opt = i;
                if (qopts[i].has_argument == 0) {
                   parsed[opt] = subtoken;
                   break;
                }
             }
          }

          if (i == nqopts && opt < 0)
             /* unknown token */
             return -RABOOTP_QS_UNKNOWN;

       } else {
          parsed[opt] = subtoken;
          break;
       }
   }

   if (opt >= 0 && qopts[opt].has_argument &&
       parsed[opt] == NULL)
      /* options takes argument but none given */
      return -RABOOTP_QS_NEEDARG;

   return 0;
}

int
RabootpParseQueryString(const struct QueryOptsStruct * const qopts,
                        size_t nqopts, char *in, char *parsed[])
{
   char *str1, *token;
   char *saveptr1;
   int j;
   int err;

   for (j = 1, str1 = in; ; j++, str1 = NULL) {
       token = strtok_r(str1, ",", &saveptr1);
       if (token == NULL)
           break;
       str1 = NULL;

       err = __parse_subtoken(qopts, nqopts, token, parsed);
       if (err < 0)
          return err;
   }
   return 0;
}
