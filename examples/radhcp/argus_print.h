#ifndef __ARGUS_PRINT_H
# define __ARGUS_PRINT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <stddef.h>
# include <sys/types.h>
# include "argus_util.h"
# include "argus_parser.h"

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


# if defined(ARGUS_MYSQL)
#  include <mysql.h>
#  define ASSIGN_ARGUS_SQL_BIND(b) .sql_bind = (b)
struct ArgusPrinterTable;
typedef int (*ArgusSQLBind)(MYSQL_BIND *b, 
                            const struct ArgusParserStruct * const,
                            const struct ArgusPrinterTable * const,
                            const void * const,
                            const struct ArgusFormatterTable * const);
# else
#  define ASSIGN_ARGUS_SQL_BIND(b) .sql_bind = NULL
typedef void *ArgusSQLBind;
# endif
/* enable flags for ArgusPrinterTable->enabled */
# define ENA_DISPLAY            0x1
# define ENA_SQL_LEASE_SUMMARY  0x2
# define ENA_SQL_LEASE_DETAIL   0x4

typedef ssize_t (*ArgusPrinter)(const struct ArgusParserStruct * const,
                                const void * const, char *, size_t);

struct ArgusPrinterTable {
   ArgusPrinter printer;       /* function to format as text */
   ArgusSQLBind sql_bind;      /* bind parameter for prepared statement */
   const char * const label;   /* display name */
   const char * const sqltype; /* SQL data type for this element */
   unsigned offset;            /* offset into structure */
   unsigned enabled;           /* see ENA_* flags above */
};


# define ARGUS_PRINT_INITIALIZER(typename, fieldname, l, func, s, e, b) \
   { .printer = (func),                                                 \
     .label = (l),                                                      \
     .offset = offsetof(struct typename, fieldname),                    \
     .sqltype = (s),                                                    \
     .enabled = (e),                                                    \
     ASSIGN_ARGUS_SQL_BIND(b),                                          \
   }

static inline
ssize_t ArgusPrintField(const struct ArgusParserStruct * const parser,
                        const struct ArgusPrinterTable * const table,
                        const void * const ptr,        /* structure */
                        unsigned idx, char *out, size_t outlen)
{
   if ((table[idx].enabled & ENA_DISPLAY) == 0)
      return 0;
   return table[idx].printer(parser, ((char *)ptr)+table[idx].offset, out,
                             outlen);
}

# if defined(ARGUS_MYSQL)
static ssize_t
__sql_field_data(char *out, size_t len,
                 enum ArgusFormatterDataType type,
                 const char * const value)
{
   if (type == DataTypeNumber)
      return snprintf(out, len, "%s", value);
   else if (type == DataTypeString)
      return snprintf(out, len, "%s", value);
   else if (type == DataTypeBoolean)
      return snprintf(out, len, "%s", value ? "true" : "false");
   return 0;
}

static const struct ArgusFormatterTable ArgusSQLFormatterTable = {
   .fieldData = __sql_field_data,
};

static inline
int ArgusPrintFieldSQL(const struct ArgusParserStruct * const parser,
                        const struct ArgusPrinterTable * const table,
                        const void * const ptr,        /* structure */
                        unsigned idx, MYSQL_BIND *b)
{
   int rv;

   if (table[idx].enabled <= ENA_DISPLAY)
      return 0;
   rv = table[idx].sql_bind(b, parser, &table[idx],
                            ((char *)ptr)+table[idx].offset,
                            &ArgusSQLFormatterTable);
   if (rv == 0)
      return 1;
   return 0;
}
# endif
#endif
