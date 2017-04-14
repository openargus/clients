#ifndef __ARGUS_PRINT_H
# define __ARGUS_PRINT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <stddef.h>
# include <sys/types.h>
# include "argus_util.h"
# include "argus_parser.h"

typedef ssize_t (*ArgusPrinter)(const struct ArgusParserStruct * const,
                                const void * const, char *, size_t);

struct ArgusPrinterTable {
   ArgusPrinter printer;     /* function to format as text */
   const char * const label; /* display name */
   unsigned offset;          /* offset into structure */
   unsigned enabled;         /* 1 == enabled (print), 0 == disabled */
};


# define ARGUS_PRINT_INITIALIZER(typename, fieldname, l, func, e) \
   { .printer = (func),                                           \
     .label = (l),                                                \
     .offset = offsetof(struct typename, fieldname),              \
     .enabled = (e),                                              \
   }

static inline
ssize_t ArgusPrintField(const struct ArgusParserStruct * const parser,
                        const struct ArgusPrinterTable * const table,
                        const void * const ptr,        /* structure */
                        unsigned idx, char *out, size_t outlen)
{
   if (table[idx].enabled == 0)
      return 0;
   return table[idx].printer(parser, ((char *)ptr)+table[idx].offset, out,
                             outlen);
}

/* formatting helpers for specific output styles (xml, json, csv, etc.) */
enum ArgusFormatterDataType {
   DataTypeNumber,
   DataTypeString,
   DataTypeBoolean,
};
typedef ssize_t (*ArgusFormatterStructureFunc)(char *out, size_t len,
                                               const char * const label);
typedef ssize_t (*ArgusFormatterDataFunc)(char * out, size_t len,
                                          enum ArgusFormatterDataType type,
                                          const char * const value);
struct ArgusFormatterTable {
   ArgusFormatterStructureFunc docStart;
   ArgusFormatterStructureFunc recordStart;
   ArgusFormatterStructureFunc fieldStart;
   ArgusFormatterStructureFunc fieldName;
   ArgusFormatterDataFunc fieldData;
   ArgusFormatterStructureFunc fieldSeparate;
   ArgusFormatterStructureFunc fieldEnd;
   ArgusFormatterStructureFunc recordSeparate;
   ArgusFormatterStructureFunc recordEnd;
   ArgusFormatterStructureFunc docEnd;
};

#endif
