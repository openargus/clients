/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 */

/*
 * Argus json parsing routines.  Adapted from HarryDC / JsonParser
 *     Copyright (c) 2017, Harald Scheirich
 *     All rights reserved.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/gargoyle/clients/common/argus_json.c#20 $
 * $DateTime: 2016/10/24 12:10:50 $
 * $Change: 3226 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <ctype.h>
#include <stddef.h>

#include "argus_debug.h"
#include "argus_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void skip_whitespace(const char**);
int has_char(const char**, char);

int json_parse_array(const char**, ArgusJsonValue *);
int json_parse_object(const char**, ArgusJsonValue *);
int json_parse_value(const char **, ArgusJsonValue *);
char *json_print_value(ArgusJsonValue *parent, char *, int);
int json_merge_value(ArgusJsonValue *, ArgusJsonValue *);

// Allocate the data structure for the vector
void
vector_init(vector* v, size_t data_size) {
   if (v == NULL) return;
   
   v->data = malloc(data_size);
   if (v->data != NULL) {
      v->capacity = 1;
      v->data_size = data_size;
      v->size = 0; 
   }
}

// Free the memory of the vector, the pointer to the vector is invalid after this
void
vector_free(vector* v) {
   if (v) {
      free(v->data);
      v->data = NULL;
   }
}

void
vector_zero(vector* v) {
   if (v) {
      v->data = NULL;
   }
}

// Return the element at index, does not do a range check
void *
vector_get(const vector* v, size_t index) {
   return &(v->data[index * v->data_size]);
}

// Return the element at index, return NULL if index is out of range for the vector
void *
vector_get_checked(const vector* v, size_t index) {
   return (index < v->size) ? &(v->data[index * v->data_size]) : NULL;
}

// if capacity < new_capacity realloc up to new_capacity
void
vector_reserve(vector* v, size_t new_capacity) {
   if (new_capacity <= v->capacity) return;
    void* new_data = realloc(v->data, new_capacity*v->data_size);
    if (new_data) {
        v->capacity = new_capacity;
        v->data = new_data;
    }
    else {
        abort();
    }
}

// Puts a non-null element data[size * data_size], will reserve more space if size == capacity
void
vector_push_back(vector* v, void* data) {
   if (v == NULL) return;

   if (((ArgusJsonValue *)data)->type != ARGUS_JSON_NULL) {
      if (v->size >= v->capacity) {
         size_t new_capacity = (v->capacity > 0) ? (size_t)(v->capacity * 2) : 1;
         vector_reserve(v, new_capacity);
       }
       memcpy(vector_get(v,v->size), data, v->data_size);
       ++v->size;
   }
}

void
vector_foreach_data(const vector* v, vector_foreach_data_t fp, void* data) {
   if (v == NULL) return;
   char* item = v->data;
   size_t i;

   if (item != NULL) {
      for (i = 0; i < v->size; i++) {
         if (! fp(item, (void *)data)) break;
         item += v->data_size;
      }
   }
}

void
vector_foreach_print(const vector* v, ArgusJsonValue *parent, vector_foreach_print_t fp, char *buf, int len) {
   if (v == NULL) return;
   char* item = v->data;
   size_t i;
   if (item != NULL) {
      for (i = 0; i < v->size; i++) {
         int slen = strlen(buf);
         if (fp == (vector_foreach_print_t) json_print_value) {
            if (((ArgusJsonValue *)item)->type) {
               fp(item, &buf[slen], len - slen);
               switch (parent->type) {
                  case ARGUS_JSON_OBJECT: {
                     int objs = v->size / 2;
                     if (objs > 1) {
                        if ((i % 2) && ((i / 2) < (objs - 1))) {
                           slen = strlen(buf);
                           snprintf (&buf[slen], len - slen, ",");
                        }
                     }
                     break;
                  }

                  case ARGUS_JSON_ARRAY: {
                     if (v->size > 1) {
                        if (i < (v->size - 1)) {
                           slen = strlen(buf);
                           snprintf (&buf[slen], len - slen, ",");
                        }
                     }
                     break;
                  }
               }
            }
         }
         item += v->data_size;
      }
   }
}

void
vector_foreach(const vector* v, ArgusJsonValue *parent, vector_foreach_t fp) {
   if (v == NULL) return;
   char* item = v->data;
   size_t i;
   if (item != NULL) {
      for (i = 0; i < v->size; i++) {
         fp(item);
         if (fp == (vector_foreach_t) json_print_value) {
            if (parent->type == ARGUS_JSON_ARRAY) {
            if (v->size > 1) {
               if (i < (v->size - 1)) {
                  printf (",");
               }
            }
         }
         }
         item += v->data_size;
      }
   }
}

void
skip_whitespace(const char** cursor) {
   if (**cursor == '\0') return;
   while (iscntrl(**cursor) || isspace(**cursor)) ++(*cursor);
}

int
has_char(const char** cursor, char character) {
   skip_whitespace(cursor);
   int retn = **cursor == character;
   if (retn) ++(*cursor);
   return retn;
}

int
json_parse_object(const char** cursor, ArgusJsonValue *parent) {
   ArgusJsonValue result = { .type = ARGUS_JSON_OBJECT };
   vector_init(&result.value.object, sizeof(ArgusJsonValue));

   int retn = 1;
   while (retn && !has_char(cursor, '}')) {
      ArgusJsonValue key = { .type = ARGUS_JSON_KEY };
      ArgusJsonValue value = { .type = ARGUS_JSON_NULL };
      retn = json_parse_value(cursor, &key);
      retn = retn && has_char(cursor, ':');
      retn = 0;
      retn = json_parse_value(cursor, &value);

#ifdef ARGUSDEBUG
      ArgusDebug (3, "json_parse_object: pushing (%s)", key.value.string);
#endif

      if (retn) {
         vector_push_back(&result.value.object, &key);
         vector_push_back(&result.value.object, &value);
      } else {
         json_free_value(&key);
      }
      skip_whitespace(cursor);
      if (has_char(cursor, '}')) break;
      else if (has_char(cursor, ',')) continue;
      else retn = 0;
   }

   if (retn) {
      *parent = result;
   } else {
      json_free_value(&result);
   }

   return retn;
   return 1;
}

int
json_parse_array(const char** cursor, ArgusJsonValue *parent) {
   int retn = 1;
   if (**cursor == ']') {
      ++(*cursor);
      return retn;
   }
   while (retn) {
      ArgusJsonValue new_value = { .type = ARGUS_JSON_NULL };
      retn = json_parse_value(cursor, &new_value);
      if (!retn) break;
      skip_whitespace(cursor);
      vector_push_back(&parent->value.array, &new_value);
      skip_whitespace(cursor);
      if (has_char(cursor, ']')) break;
      else if (has_char(cursor, ',')) continue;
      else retn = 0;
   }
   return retn;
}


void
json_free_value(ArgusJsonValue *val) {
   if (!val) return;

   switch (val->type) {
      case ARGUS_JSON_KEY:
      case ARGUS_JSON_STRING:
         if (val->value.string != NULL) {
            free(val->value.string);
            val->value.string = NULL;
	 }
         break;
      case ARGUS_JSON_ARRAY:
      case ARGUS_JSON_OBJECT:
         vector_foreach(&(val->value.array), val, (void(*)(void*))json_free_value);
         vector_free(&(val->value.array));
         break;
   }
   val->type = ARGUS_JSON_NULL;
}


void
json_zero_value(ArgusJsonValue *val) {
   if (!val) return;

   switch (val->type) {
      case ARGUS_JSON_STRING:
         break;

      case ARGUS_JSON_ARRAY:
      case ARGUS_JSON_OBJECT:
         vector_foreach(&(val->value.array), val, (void(*)(void*))json_zero_value);
         vector_zero(&(val->value.array));
         break;
   }
   val->type = ARGUS_JSON_NULL;
}

int
json_is_literal(const char** cursor, const char* literal) {
   size_t cnt = strlen(literal);
   if (strncmp(*cursor, literal, cnt) == 0) {
      *cursor += cnt;
      return 1;
   }
   return 0;
}

int
json_parse_value(const char** cursor, ArgusJsonValue *parent) {
   // Eat whitespace
   int retn = 0;
   skip_whitespace(cursor);
   switch (**cursor) {
      case '\0':
         // If parse_value is called with the cursor at the end of the string
         // that's a failure
         retn = 0;
         break;
      case '"': {
         ++*cursor;
         const char *start = *cursor;
         char *end = strchr(*cursor, '"');
         if (end != NULL) {
            while ((end[-1] == '\\') && (end[-2] != '\\')) {
               end = strchr(++end, '"');
            }
         }
         if (end) {
            size_t len = end - start;
            char *new_string = malloc((len + 1) * sizeof(char));
            memcpy(new_string, start, len);
            new_string[len] = '\0';

            if ((parent->type == ARGUS_JSON_KEY) ||
                (parent->type == ARGUS_JSON_STRING)) {
               if (parent->value.string != NULL) {
                  free (parent->value.string);
                  parent->value.string = NULL;
               }
            }

            if (parent->type != ARGUS_JSON_KEY) {
               parent->type = ARGUS_JSON_STRING;
            }
            parent->value.string = new_string;
            *cursor = end + 1;
            retn = 1;
         }
         break;
      }

      case '{':
         ++(*cursor);
         skip_whitespace(cursor);
         retn = json_parse_object(cursor, parent);
         break;

      case '[':
         parent->type = ARGUS_JSON_ARRAY;
         vector_init(&parent->value.array, sizeof(ArgusJsonValue));
         ++(*cursor);
         skip_whitespace(cursor);
         retn = json_parse_array(cursor, parent);
         if (!retn) {
            vector_free(&parent->value.array);
         }
         break;
      case 't': {
         retn = json_is_literal(cursor, "true");
         if (retn) {
            parent->type = ARGUS_JSON_BOOL;
            parent->value.boolean = 1;
         }
         break;
      }
      case 'f': {
         retn = json_is_literal(cursor, "false");
         if (retn) {
            parent->type = ARGUS_JSON_BOOL;
            parent->value.boolean = 0;
         }
         break;
      }
      case 'n':
         retn = json_is_literal(cursor, "null");
         break;

      default: {
         const char* start = *cursor;
         char *end;
         double number = strtod(*cursor, &end);
         if (*cursor != end) {
            if (number == (int) number) {
               parent->type = ARGUS_JSON_INTEGER;
            } else {
               parent->type = ARGUS_JSON_DOUBLE;
            }
            parent->value.number = number;
            *cursor = end;
            retn = 1;
         } else {
            if ((end = strchr(*cursor, ',')) || (end = strchr(*cursor, '}'))) {
               size_t len = end - start;
               char *new_string = malloc((len + 1) * sizeof(char));
               memcpy(new_string, start, len);
               new_string[len] = '\0';

               if ((parent->type == ARGUS_JSON_KEY) ||
                   (parent->type == ARGUS_JSON_STRING)) {
                  if (parent->value.string != NULL)
                     free (parent->value.string);
               }

               if (parent->type != ARGUS_JSON_KEY) {
                  parent->type = ARGUS_JSON_STRING;
               }
               parent->value.string = new_string;
               *cursor = end + 1;
               retn = 1;
            }
         }
      }
   }
   return retn;
}

char *
json_print_value(ArgusJsonValue *parent, char *buf, int len) {
   char *retn = NULL;
   int slen;

   switch (parent->type) {
      case ARGUS_JSON_BOOL:
         snprintf (buf, len, "%s", parent->value.boolean ? "true" : "false");
         break;
      case ARGUS_JSON_INTEGER:
         snprintf (buf, len, "%d", (int)parent->value.number);
         break;
      case ARGUS_JSON_DOUBLE:
         snprintf (buf, len, "%f", parent->value.number);
         break;
      case ARGUS_JSON_KEY: {
         snprintf (buf, len, "\"%s\":", parent->value.string);
         break;
      }
      case ARGUS_JSON_STRING: {
         snprintf (buf, len, "\"%s\"", parent->value.string);
         break;
      }
      case ARGUS_JSON_ARRAY: {
         snprintf (buf, len, "[");
         vector_foreach_print(&(parent->value.array), parent, (vector_foreach_print_t)json_print_value, buf + 1, len - 1);
         slen = strlen(buf);
         snprintf (&buf[slen], len - slen, "]");
         break;
      }
      case ARGUS_JSON_OBJECT: {
         snprintf (buf, len, "{");
         vector_foreach_print(&(parent->value.array), parent, (vector_foreach_print_t)json_print_value, buf + 1, len - 1);
         slen = strlen(buf);
         snprintf (&buf[slen], len - slen, "}");
         break;
      }
   }
   return retn;
}

int json_add_value(ArgusJsonValue *, ArgusJsonValue *);

int
json_add_value(ArgusJsonValue *p1, ArgusJsonValue *p2) {
   int retn = 0;
   if ((p1->type != ARGUS_JSON_OBJECT) && (p1->type != ARGUS_JSON_ARRAY)) {
      ArgusJsonValue v1 = { .type = p1->type };
      ArgusJsonValue v2 = { .type = p2->type };

      bcopy(p1, &v1, sizeof(v1));
      bcopy(p2, &v2, sizeof(v2));

      p1->type = ARGUS_JSON_ARRAY;

      switch (p2->type) {
         case ARGUS_JSON_BOOL:
         case ARGUS_JSON_INTEGER:
         case ARGUS_JSON_DOUBLE:
            break;

         case ARGUS_JSON_STRING:
            v2.value.string = strdup(p2->value.string);
            break;
      }

      vector_init(&p1->value.object, sizeof(ArgusJsonValue));
      vector_push_back(&p1->value.array, &v1);
      vector_push_back(&p1->value.array, &v2);
      p1->status |= ARGUS_JSON_MODIFIED;

   } else {
      vector_push_back(&p1->value.array, p2);
      p1->status |= ARGUS_JSON_MODIFIED;
   }
   return retn;
}

int
json_merge_value(ArgusJsonValue *p1, ArgusJsonValue *p2) {
   int retn = 0;

   if (p1->type == p2->type) {
      switch (p1->type) {
         case ARGUS_JSON_BOOL:
            if (p1->value.boolean != p2->value.boolean) {
               p1->value.boolean = 0;
            } else
               p1->status |= ARGUS_JSON_MODIFIED;
            break;

         case ARGUS_JSON_INTEGER:
         case ARGUS_JSON_DOUBLE:
            if (p1->value.number != p2->value.number) {
               json_add_value(p1, p2);
            } else
               p1->status |= ARGUS_JSON_MODIFIED;
            break;
         case ARGUS_JSON_STRING: {
            if (strcmp(p1->value.string, p2->value.string)) {
               json_add_value(p1, p2);
               p2->type = ARGUS_JSON_NULL;
            } else
               p1->status |= ARGUS_JSON_MODIFIED;
            break;
         }
         case ARGUS_JSON_KEY: {
            break;
         }
         case ARGUS_JSON_ARRAY: {
            vector *v1 = json_value_to_array(p1);
            vector *v2 = json_value_to_array(p2);

            ArgusJsonValue *v2item = (ArgusJsonValue *)v2->data;
            size_t i, x;

            if (v2item != NULL) {
               for (i = 0; i < v2->size; i++) {
                  int p2valuefound = 0;
                  ArgusJsonValue *v1item = (ArgusJsonValue *)v1->data;

                  if (v1item != NULL) {
                     for (x = 0; x < v1->size; x++) {
                        if (v1item->type == v2item->type) {
                           switch (v1item->type) {
                              case ARGUS_JSON_BOOL:
                                 if (v1item->value.boolean == v2item->value.boolean) {
                                    p2valuefound = 1;
                                 }
                                 break;

                              case ARGUS_JSON_INTEGER:
                              case ARGUS_JSON_DOUBLE:
                                 if (v1item->value.number == v2item->value.number) {
                                    p2valuefound = 1;
                                 }
                                 break;
                              case ARGUS_JSON_STRING: {
                                 if (strcmp(v1item->value.string, v2item->value.string) == 0) {
                                    p2valuefound = 1;
                                 }
                                 break;
                              }
                              case ARGUS_JSON_KEY: {
                                 printf ("\"%s\" ... \"%s\"", p1->value.string, p2->value.string);
                                 break;
                              }
                           }
                        }
                        v1item++;
                     }
                  }
                  if (!(p2valuefound)) {
                     vector_push_back(&p1->value.array, v2item);
                     v2item->type = ARGUS_JSON_NULL;
                     p1->status |= ARGUS_JSON_MODIFIED;
                  }
                  v2item++;
               }
            }
            break;
         }
         case ARGUS_JSON_OBJECT: {
            ArgusJsonValue *p1data = (ArgusJsonValue*)p1->value.object.data;
            ArgusJsonValue *p2data = (ArgusJsonValue*)p2->value.object.data;

            size_t i, p1size = p1->value.object.size;
            size_t x, p2size = p2->value.object.size;

            for (i = 0; (i < p1size); i += 2) {
               char *key = p1data[i].value.string;
               ArgusJsonValue *p1value = &p1data[i +1];

               for (x = 0; x < p2size; x += 2) {
                  if (strcmp(p2data[x].value.string, key) == 0) {
                     ArgusJsonValue *p2value = &p2data[x + 1];
                     json_merge_value(p1value, p2value);
                     ((ArgusJsonValue *)&p2data[x])->type = ARGUS_JSON_NULL;
                     ((ArgusJsonValue *)&p2data[x + 1])->type = ARGUS_JSON_NULL;

                     if (p1value->status & ARGUS_JSON_MODIFIED) {
                        json_zero_value(&p2data[x]);
                        json_zero_value(&p2data[x + 1]);
                        p1value->status &= ~ARGUS_JSON_MODIFIED;
                     }
                     if (p2value->status & ARGUS_JSON_MODIFIED) {
                        json_zero_value(&p1data[x]);
                        json_zero_value(&p1data[x + 1]);
                        p2value->status &= ~ARGUS_JSON_MODIFIED;
                     }
                  }
               }
            }

            for (x = 0; x < p2size; x += 2) {
               if (((ArgusJsonValue *)&p2data[x])->type) {
                  vector_push_back(&p1->value.array, &p2data[x]);
                  ((ArgusJsonValue *)&p2data[x])->type = ARGUS_JSON_NULL;
                  vector_push_back(&p1->value.array, &p2data[x + 1]);
                  ((ArgusJsonValue *)&p2data[x + 1])->type = ARGUS_JSON_NULL;
                  p1->status |= ARGUS_JSON_MODIFIED;
               }
            }
            break;
         }
      }

   } else {
      if ((p1->type == ARGUS_JSON_ARRAY) || (p2->type == ARGUS_JSON_ARRAY)) {
         ArgusJsonValue *array = (p1->type == ARGUS_JSON_ARRAY) ? p1 : p2;
         ArgusJsonValue *value = (p1->type != ARGUS_JSON_ARRAY) ? p1 : p2;

         vector *v = json_value_to_array(array);
         ArgusJsonValue *aitem = (ArgusJsonValue *)v->data;
         size_t i, asize = v->size;
         int found = 0;

         for (i = 0; (i < asize) && !found; i++) {
            if (aitem->type == value->type) {
               switch (aitem->type) {
                  case ARGUS_JSON_BOOL:
                     if (aitem->value.boolean == value->value.boolean) {
                        found = 1;
                     }
                     break;

                  case ARGUS_JSON_INTEGER:
                  case ARGUS_JSON_DOUBLE:
                     if (aitem->value.number == value->value.number) {
                        found = 1;
                     }
                     break;
                  case ARGUS_JSON_STRING: {
                     if (strcmp(aitem->value.string, value->value.string) == 0) {
                        found = 1;
                     }
                     break;
                  }
                  case ARGUS_JSON_KEY: {
                     break;
                  }
               }
            }
            aitem++;
         }
         if (!found) {
            vector_push_back(v, value);
            value->type = ARGUS_JSON_NULL;
            array->status |= ARGUS_JSON_MODIFIED;
         } else
            p1->status |= ARGUS_JSON_MODIFIED;
      }
   }
   return retn;
}

ArgusJsonValue *
ArgusJsonParse(const char* input, ArgusJsonValue *result) {
   ArgusJsonValue *retn = NULL;

   if (json_parse_value(&input, result))
      retn = result;

   return (retn);
}

char *
ArgusJsonPrint(ArgusJsonValue *result, char *buf, int len) {
   json_print_value(result, buf, len);
   return buf;
}

ArgusJsonValue *
ArgusJsonMergeValues(ArgusJsonValue *res1, ArgusJsonValue *res2) {
   json_merge_value(res1, res2);
   return (res1);
}


char *
json_value_to_string(ArgusJsonValue *value)
{
   return (char *)value->value.string;
}

double
json_value_to_double(ArgusJsonValue *value) {
   return value->value.number;
}

int
json_value_to_integer(ArgusJsonValue *value) {
   return value->value.number;
}

int
json_value_to_bool(ArgusJsonValue *value) {
   return value->value.boolean;
}

vector *
json_value_to_array(ArgusJsonValue *value) {
   return &value->value.array;
}

vector *
json_value_to_object(ArgusJsonValue *value) {
   return &value->value.object;
}

ArgusJsonValue *
json_value_at(const ArgusJsonValue *root, size_t index) {
   if (root->value.array.size < index) {
      return vector_get_checked(&root->value.array,index);
   }
   else {
      return NULL;
   }
}

ArgusJsonValue *
json_value_with_key(const ArgusJsonValue *root, const char* key) {
   ArgusJsonValue *data = (ArgusJsonValue*)root->value.object.data;
   size_t i, size = root->value.object.size;
   for (i = 0; i < size; i += 2) {
      if (strcmp(data[i].value.string, key) == 0) {
         return &data[i + 1];
      }
   }
   return NULL;
}
