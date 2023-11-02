#include "argus_print.h"

static ssize_t __json_doc_start(char *out, size_t len,
                                const char * const label)
{
   return snprintf(out, len, "{");
}

static ssize_t __json_record_start(char *out, size_t len,
                                   const char * const label)
{
   return snprintf(out, len, "\"%s\": {", label);
}

static ssize_t __json_field_name(char *out, size_t len,
                                 const char * const label)
{
   return snprintf(out, len, "\"%s\": ", label);
}

static ssize_t __json_field_data(char *out, size_t len,
                                 enum ArgusFormatterDataType type,
                                 const char * const value)
{
   if (type == DataTypeNumber)
      return snprintf(out, len, "%s", value);
   else if (type == DataTypeString)
      return snprintf(out, len, "\"%s\"", value);
   else if (type == DataTypeBoolean)
      return snprintf(out, len, "%s", value ? "true" : "false");
   return 0;
}

static ssize_t __json_field_separate(char *out, size_t len,
                                     const char * const label)
{
   return snprintf(out, len, ", ");
}

static ssize_t __json_record_separate(char *out, size_t len,
                                      const char * const label)
{
   return snprintf(out, len, ", ");
}

static ssize_t __json_record_end(char *out, size_t len,
                                 const char * const label)
{
   return snprintf(out, len, "}");
}

static ssize_t __json_doc_end(char *out, size_t len,
                              const char * const label)
{
   return snprintf(out, len, "}");
}

static ssize_t __json_obj_only_start(char *out, size_t len,
                                     const char * const label)
{
   /* category can later become a field based on "confidence" */
   return snprintf(out, len, "{\"rank\": \"%s\", \"category\": \"ff\", ",
                   label);
}

static ssize_t __newline(char *out, size_t len, const char * const label)
{
   return snprintf(out, len, "\n");
}

/*
const struct ArgusFormatterTable ArgusJsonFormatterTable = {
   .docStart = __json_doc_start,
   .recordStart = __json_record_start,
   .fieldStart = NULL,
   .fieldName = __json_field_name,
   .fieldData = __json_field_data,
   .fieldSeparate = __json_field_separate,
   .fieldEnd = NULL,
   .recordSeparate = __json_record_separate,
   .recordEnd = __json_record_end,
   .docEnd = __json_doc_end,
};

const struct ArgusFormatterTable ArgusJsonObjOnlyFormatterTable = {
   .docStart = NULL,
   .recordStart = __json_obj_only_start,
   .fieldStart = NULL,
   .fieldName = __json_field_name,
   .fieldData = __json_field_data,
   .fieldSeparate = __json_field_separate,
   .fieldEnd = NULL,
   .recordSeparate = __newline,
   .recordEnd = __json_record_end,
   .docEnd = NULL,
};
*/
