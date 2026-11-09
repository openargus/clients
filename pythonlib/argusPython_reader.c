/*
 * Binary-first reader implementation for the argusPython extension.
 *
 * The Argus parser remains process-global.  A reader therefore owns it only
 * while run() is active and records are copied before the parser reuses its
 * input buffer.
 */

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#define PY_ARRAY_UNIQUE_SYMBOL ARGUS_PYTHON_ARRAY_API
#define NO_IMPORT_ARRAY

#include <Python.h>
#include <numpy/arrayobject.h>

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_main.h>
#include <argus_client.h>
#include <argus_metric.h>
#include <argus_filter.h>
#include <argus_threads.h>
#include <argus_radsrs.h>

#include "argusPython_reader.h"

#define ARGUS_PYTHON_READER_CAPSULE "argusPython.Reader"
#define ARGUS_PYTHON_DEFAULT_BATCH_SIZE 65536UL
#define ARGUS_PYTHON_DEFAULT_MAX_BYTES (8UL * 1024UL * 1024UL)

#define READER_FIELD_SEQUENCE       (1U << 0)
#define READER_FIELD_RECORD_TYPE    (1U << 1)
#define READER_FIELD_VERSION        (1U << 2)
#define READER_FIELD_START_TIME     (1U << 3)
#define READER_FIELD_END_TIME       (1U << 4)
#define READER_FIELD_FLOW_VALID     (1U << 5)
#define READER_FIELD_SRC_ADDR       (1U << 6)
#define READER_FIELD_DST_ADDR       (1U << 7)
#define READER_FIELD_PROTOCOL       (1U << 8)
#define READER_FIELD_SRC_PORT       (1U << 9)
#define READER_FIELD_DST_PORT       (1U << 10)
#define READER_FIELD_METRICS_VALID  (1U << 11)
#define READER_FIELD_SRC_PACKETS    (1U << 12)
#define READER_FIELD_DST_PACKETS    (1U << 13)
#define READER_FIELD_SRC_BYTES      (1U << 14)
#define READER_FIELD_DST_BYTES      (1U << 15)
#define READER_FIELD_RAW            (1U << 16)
#define READER_FIELD_FIDELITY       (1U << 17)
#define READER_FIELD_ALL            ((1U << 18) - 1U)

enum ArgusPythonReaderSourceType {
   ARGUS_PYTHON_SOURCE_FILE,
   ARGUS_PYTHON_SOURCE_STDIN,
   ARGUS_PYTHON_SOURCE_SERVER
};

enum ArgusPythonReaderMode {
   ARGUS_PYTHON_READER_IDLE,
   ARGUS_PYTHON_READER_RECORDS,
   ARGUS_PYTHON_READER_BATCHES
};

enum ArgusPythonFidelity {
   ARGUS_PYTHON_FIDELITY_NO_RAW,
   ARGUS_PYTHON_FIDELITY_EXACT_NATIVE,
   ARGUS_PYTHON_FIDELITY_DERIVED_CURRENT,
   ARGUS_PYTHON_FIDELITY_DERIVED_LEGACY
};

struct ArgusPythonReaderSource {
   struct ArgusPythonReaderSource *next;
   enum ArgusPythonReaderSourceType type;
   char *value;
};

struct ArgusPythonReaderBatch {
   npy_intp capacity;
   npy_intp count;
   size_t raw_length;
   PyArrayObject *sequence;
   PyArrayObject *record_type;
   PyArrayObject *version;
   PyArrayObject *start_time_ns;
   PyArrayObject *end_time_ns;
   PyArrayObject *flow_valid;
   PyArrayObject *src_addr;
   PyArrayObject *dst_addr;
   PyArrayObject *protocol;
   PyArrayObject *src_port;
   PyArrayObject *dst_port;
   PyArrayObject *metrics_valid;
   PyArrayObject *src_packets;
   PyArrayObject *dst_packets;
   PyArrayObject *src_bytes;
   PyArrayObject *dst_bytes;
   PyArrayObject *raw_data;
   PyArrayObject *raw_offsets;
   PyArrayObject *raw_valid;
   PyArrayObject *fidelity;
};

struct ArgusPythonReader {
   struct ArgusParserStruct *parser;
   struct ArgusPythonReaderSource *sources;
   struct ArgusPythonReaderSource *sources_tail;
   struct ArgusPythonReaderBatch batch;
   PyObject *callback;
   char *filter;
   unsigned int fields;
   unsigned long batch_size;
   unsigned long max_bytes;
   unsigned long sequence;
   unsigned long records;
   enum ArgusPythonReaderMode mode;
   int closed;
   int remote_filter_fallback;
};

static struct ArgusPythonReader *ArgusPythonActiveReader;

extern struct ArgusParserStruct *ArgusParser;

static void
ArgusPythonReaderBatchClear(struct ArgusPythonReaderBatch *batch)
{
   Py_CLEAR(batch->sequence);
   Py_CLEAR(batch->record_type);
   Py_CLEAR(batch->version);
   Py_CLEAR(batch->start_time_ns);
   Py_CLEAR(batch->end_time_ns);
   Py_CLEAR(batch->flow_valid);
   Py_CLEAR(batch->src_addr);
   Py_CLEAR(batch->dst_addr);
   Py_CLEAR(batch->protocol);
   Py_CLEAR(batch->src_port);
   Py_CLEAR(batch->dst_port);
   Py_CLEAR(batch->metrics_valid);
   Py_CLEAR(batch->src_packets);
   Py_CLEAR(batch->dst_packets);
   Py_CLEAR(batch->src_bytes);
   Py_CLEAR(batch->dst_bytes);
   Py_CLEAR(batch->raw_data);
   Py_CLEAR(batch->raw_offsets);
   Py_CLEAR(batch->raw_valid);
   Py_CLEAR(batch->fidelity);
   batch->count = 0;
   batch->raw_length = 0;
}

static PyArrayObject *
ArgusPythonReaderNewArray(int type, npy_intp length)
{
   npy_intp dimensions[1];

   dimensions[0] = length;
   return (PyArrayObject *)PyArray_SimpleNew(1, dimensions, type);
}

static int
ArgusPythonReaderBatchReset(struct ArgusPythonReader *reader)
{
   struct ArgusPythonReaderBatch *batch = &reader->batch;
   npy_intp capacity = (npy_intp)reader->batch_size;

   ArgusPythonReaderBatchClear(batch);
   batch->capacity = capacity;

#define ARGUS_PYTHON_ALLOCATE(member, bit, type, length) \
   do { \
      if ((reader->fields & (bit)) != 0) { \
         batch->member = ArgusPythonReaderNewArray((type), (length)); \
         if (batch->member == NULL) \
            goto failed; \
      } \
   } while (0)

   ARGUS_PYTHON_ALLOCATE(sequence, READER_FIELD_SEQUENCE, NPY_UINT64, capacity);
   ARGUS_PYTHON_ALLOCATE(record_type, READER_FIELD_RECORD_TYPE, NPY_UINT8, capacity);
   ARGUS_PYTHON_ALLOCATE(version, READER_FIELD_VERSION, NPY_UINT8, capacity);
   ARGUS_PYTHON_ALLOCATE(start_time_ns, READER_FIELD_START_TIME, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(end_time_ns, READER_FIELD_END_TIME, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(flow_valid, READER_FIELD_FLOW_VALID, NPY_BOOL, capacity);
   ARGUS_PYTHON_ALLOCATE(src_addr, READER_FIELD_SRC_ADDR, NPY_UINT32, capacity);
   ARGUS_PYTHON_ALLOCATE(dst_addr, READER_FIELD_DST_ADDR, NPY_UINT32, capacity);
   ARGUS_PYTHON_ALLOCATE(protocol, READER_FIELD_PROTOCOL, NPY_UINT8, capacity);
   ARGUS_PYTHON_ALLOCATE(src_port, READER_FIELD_SRC_PORT, NPY_UINT16, capacity);
   ARGUS_PYTHON_ALLOCATE(dst_port, READER_FIELD_DST_PORT, NPY_UINT16, capacity);
   ARGUS_PYTHON_ALLOCATE(metrics_valid, READER_FIELD_METRICS_VALID, NPY_BOOL, capacity);
   ARGUS_PYTHON_ALLOCATE(src_packets, READER_FIELD_SRC_PACKETS, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(dst_packets, READER_FIELD_DST_PACKETS, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(src_bytes, READER_FIELD_SRC_BYTES, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(dst_bytes, READER_FIELD_DST_BYTES, NPY_INT64, capacity);
   ARGUS_PYTHON_ALLOCATE(fidelity, READER_FIELD_FIDELITY, NPY_UINT8, capacity);
   if ((reader->fields & READER_FIELD_RAW) != 0) {
      batch->raw_data = ArgusPythonReaderNewArray(NPY_UINT8,
                                                   (npy_intp)reader->max_bytes);
      batch->raw_offsets = ArgusPythonReaderNewArray(NPY_UINT64, capacity + 1);
      batch->raw_valid = ArgusPythonReaderNewArray(NPY_BOOL, capacity);
      if ((batch->raw_data == NULL) || (batch->raw_offsets == NULL) ||
          (batch->raw_valid == NULL))
         goto failed;
      *(npy_uint64 *)PyArray_GETPTR1(batch->raw_offsets, 0) = 0;
   }

#undef ARGUS_PYTHON_ALLOCATE
   return 0;

failed:
   ArgusPythonReaderBatchClear(batch);
   return -1;
}

static int
ArgusPythonReaderAddSlice(PyObject *columns, const char *name,
                          PyArrayObject *array, npy_intp end)
{
   PyObject *start = NULL;
   PyObject *stop = NULL;
   PyObject *slice = NULL;
   PyObject *view = NULL;
   int result = -1;

   if (array == NULL)
      return 0;
   start = PyLong_FromLong(0);
   stop = PyLong_FromSsize_t((Py_ssize_t)end);
   if ((start == NULL) || (stop == NULL))
      goto done;
   slice = PySlice_New(start, stop, NULL);
   if (slice == NULL)
      goto done;
   view = PyObject_GetItem((PyObject *)array, slice);
   if (view == NULL)
      goto done;
   if (PyDict_SetItemString(columns, name, view) < 0)
      goto done;
   result = 0;

done:
   Py_XDECREF(view);
   Py_XDECREF(slice);
   Py_XDECREF(stop);
   Py_XDECREF(start);
   return result;
}

static int
ArgusPythonReaderFlushBatch(struct ArgusPythonReader *reader)
{
   struct ArgusPythonReaderBatch *batch = &reader->batch;
   PyObject *columns = NULL;
   PyObject *count = NULL;
   PyObject *payload = NULL;
   PyObject *result = NULL;
   int status = -1;

   if (batch->count == 0)
      return 0;

   columns = PyDict_New();
   if (columns == NULL)
      goto done;

#define ARGUS_PYTHON_ADD_SLICE(name, member, end) \
   do { \
      if (ArgusPythonReaderAddSlice(columns, (name), batch->member, (end)) < 0) \
         goto done; \
   } while (0)

   ARGUS_PYTHON_ADD_SLICE("sequence", sequence, batch->count);
   ARGUS_PYTHON_ADD_SLICE("record_type", record_type, batch->count);
   ARGUS_PYTHON_ADD_SLICE("version", version, batch->count);
   ARGUS_PYTHON_ADD_SLICE("start_time_ns", start_time_ns, batch->count);
   ARGUS_PYTHON_ADD_SLICE("end_time_ns", end_time_ns, batch->count);
   ARGUS_PYTHON_ADD_SLICE("flow_valid", flow_valid, batch->count);
   ARGUS_PYTHON_ADD_SLICE("src_addr", src_addr, batch->count);
   ARGUS_PYTHON_ADD_SLICE("dst_addr", dst_addr, batch->count);
   ARGUS_PYTHON_ADD_SLICE("protocol", protocol, batch->count);
   ARGUS_PYTHON_ADD_SLICE("src_port", src_port, batch->count);
   ARGUS_PYTHON_ADD_SLICE("dst_port", dst_port, batch->count);
   ARGUS_PYTHON_ADD_SLICE("metrics_valid", metrics_valid, batch->count);
   ARGUS_PYTHON_ADD_SLICE("src_packets", src_packets, batch->count);
   ARGUS_PYTHON_ADD_SLICE("dst_packets", dst_packets, batch->count);
   ARGUS_PYTHON_ADD_SLICE("src_bytes", src_bytes, batch->count);
   ARGUS_PYTHON_ADD_SLICE("dst_bytes", dst_bytes, batch->count);
   ARGUS_PYTHON_ADD_SLICE("fidelity", fidelity, batch->count);
   if (batch->raw_data != NULL) {
      ARGUS_PYTHON_ADD_SLICE("raw_data", raw_data, (npy_intp)batch->raw_length);
      ARGUS_PYTHON_ADD_SLICE("raw_offsets", raw_offsets, batch->count + 1);
      ARGUS_PYTHON_ADD_SLICE("raw_valid", raw_valid, batch->count);
   }

#undef ARGUS_PYTHON_ADD_SLICE

   count = PyLong_FromSsize_t((Py_ssize_t)batch->count);
   if (count == NULL)
      goto done;
   payload = PyTuple_Pack(2, columns, count);
   if (payload == NULL)
      goto done;
   result = PyObject_CallOneArg(reader->callback, payload);
   if (result == NULL)
      goto done;
   Py_CLEAR(result);

   if (ArgusPythonReaderBatchReset(reader) < 0)
      goto done;
   status = 0;

done:
   Py_XDECREF(result);
   Py_XDECREF(payload);
   Py_XDECREF(count);
   Py_XDECREF(columns);
   if (status < 0 && reader->parser != NULL)
      reader->parser->RaParseDone = 1;
   return status;
}

static long long
ArgusPythonReaderUsecToNsec(long long usec)
{
   if (usec > (LLONG_MAX / 1000LL))
      return LLONG_MAX;
   if (usec < (LLONG_MIN / 1000LL))
      return LLONG_MIN;
   return usec * 1000LL;
}

static unsigned char
ArgusPythonReaderFidelity(const char *fidelity)
{
   if (fidelity == NULL)
      return ARGUS_PYTHON_FIDELITY_NO_RAW;
   if (!strcmp(fidelity, "exact_native_v3_v5"))
      return ARGUS_PYTHON_FIDELITY_EXACT_NATIVE;
   if (!strcmp(fidelity, "derived_current_format"))
      return ARGUS_PYTHON_FIDELITY_DERIVED_CURRENT;
   if (!strcmp(fidelity, "derived_or_legacy"))
      return ARGUS_PYTHON_FIDELITY_DERIVED_LEGACY;
   return ARGUS_PYTHON_FIDELITY_NO_RAW;
}

static int
ArgusPythonReaderAppendBatch(struct ArgusPythonReader *reader,
                             struct ArgusRecordStruct *record)
{
   struct ArgusPythonReaderBatch *batch = &reader->batch;
   const unsigned char *raw = NULL;
   size_t raw_length = 0;
   int have_raw;
   npy_intp row;
   struct ArgusFlow *flow;
   struct ArgusMetricStruct *metric;
   int flow_is_ipv4 = 0;
   const char *fidelity;

   have_raw = ArgusRadsrsGetRawRecord(record, &raw, &raw_length);
   if (batch->count == batch->capacity ||
       ((batch->raw_data != NULL) && (batch->count > 0) && have_raw &&
        (raw_length > (reader->max_bytes - batch->raw_length)))) {
      if (ArgusPythonReaderFlushBatch(reader) < 0)
         return -1;
      batch = &reader->batch;
   }

   if ((batch->raw_data != NULL) && have_raw && (raw_length > reader->max_bytes)) {
      PyErr_Format(PyExc_ValueError,
                   "record raw data (%zu bytes) exceeds max_bytes (%lu)",
                   raw_length, reader->max_bytes);
      if (reader->parser != NULL)
         reader->parser->RaParseDone = 1;
      return -1;
   }

   row = batch->count;
   flow = (struct ArgusFlow *)record->dsrs[ARGUS_FLOW_INDEX];
   metric = (struct ArgusMetricStruct *)record->dsrs[ARGUS_METRIC_INDEX];
   if ((flow != NULL) &&
       ((flow->hdr.subtype & 0x3f) == ARGUS_FLOW_CLASSIC5TUPLE) &&
       ((flow->hdr.argus_dsrvl8.qual & 0x1f) == ARGUS_TYPE_IPV4))
      flow_is_ipv4 = 1;
   fidelity = ArgusRadsrsRecordFidelity(record, raw, raw_length);

#define ARGUS_PYTHON_SET(member, type, value) \
   do { \
      if (batch->member != NULL) \
         *(type *)PyArray_GETPTR1(batch->member, row) = (value); \
   } while (0)

   ARGUS_PYTHON_SET(sequence, npy_uint64, (npy_uint64)reader->sequence);
   ARGUS_PYTHON_SET(record_type, npy_uint8, (npy_uint8)record->hdr.type);
   ARGUS_PYTHON_SET(version, npy_uint8, (npy_uint8)(record->hdr.type & ARGUS_VERSION_MASK));
   ARGUS_PYTHON_SET(start_time_ns, npy_int64,
                    (npy_int64)ArgusPythonReaderUsecToNsec(ArgusFetchStartuSecTime(record)));
   ARGUS_PYTHON_SET(end_time_ns, npy_int64,
                    (npy_int64)ArgusPythonReaderUsecToNsec(ArgusFetchLastuSecTime(record)));
   ARGUS_PYTHON_SET(flow_valid, npy_bool, (npy_bool)flow_is_ipv4);
   ARGUS_PYTHON_SET(src_addr, npy_uint32,
                    flow_is_ipv4 ? (npy_uint32)flow->ip_flow.ip_src : 0);
   ARGUS_PYTHON_SET(dst_addr, npy_uint32,
                    flow_is_ipv4 ? (npy_uint32)flow->ip_flow.ip_dst : 0);
   ARGUS_PYTHON_SET(protocol, npy_uint8,
                    flow_is_ipv4 ? (npy_uint8)flow->ip_flow.ip_p : 0);
   ARGUS_PYTHON_SET(src_port, npy_uint16,
                    flow_is_ipv4 ? (npy_uint16)flow->ip_flow.sport : 0);
   ARGUS_PYTHON_SET(dst_port, npy_uint16,
                    flow_is_ipv4 ? (npy_uint16)flow->ip_flow.dport : 0);
   ARGUS_PYTHON_SET(metrics_valid, npy_bool, (npy_bool)(metric != NULL));
   ARGUS_PYTHON_SET(src_packets, npy_int64,
                    metric != NULL ? (npy_int64)metric->src.pkts : 0);
   ARGUS_PYTHON_SET(dst_packets, npy_int64,
                    metric != NULL ? (npy_int64)metric->dst.pkts : 0);
   ARGUS_PYTHON_SET(src_bytes, npy_int64,
                    metric != NULL ? (npy_int64)metric->src.bytes : 0);
   ARGUS_PYTHON_SET(dst_bytes, npy_int64,
                    metric != NULL ? (npy_int64)metric->dst.bytes : 0);
   ARGUS_PYTHON_SET(fidelity, npy_uint8, ArgusPythonReaderFidelity(fidelity));

#undef ARGUS_PYTHON_SET

   if (batch->raw_data != NULL) {
      *(npy_bool *)PyArray_GETPTR1(batch->raw_valid, row) = (npy_bool)have_raw;
      *(npy_uint64 *)PyArray_GETPTR1(batch->raw_offsets, row) =
         (npy_uint64)batch->raw_length;
      if (have_raw && raw_length > 0) {
         memcpy(PyArray_BYTES(batch->raw_data) + batch->raw_length, raw, raw_length);
         batch->raw_length += raw_length;
      }
      *(npy_uint64 *)PyArray_GETPTR1(batch->raw_offsets, row + 1) =
         (npy_uint64)batch->raw_length;
   }

   batch->count++;
   reader->sequence++;
   reader->records++;
   if (batch->count == batch->capacity)
      return ArgusPythonReaderFlushBatch(reader);
   return 0;
}

static int
ArgusPythonReaderDeliverRecord(struct ArgusPythonReader *reader,
                               struct ArgusRecordStruct *record)
{
   const unsigned char *raw = NULL;
   size_t raw_length = 0;
   int have_raw;
   char *jsonseq = NULL;
   size_t jsonseq_length = 0;
   const char *fidelity;
   PyObject *payload = NULL;
   PyObject *value = NULL;
   PyObject *callback_result = NULL;
   int result = -1;

   have_raw = ArgusRadsrsGetRawRecord(record, &raw, &raw_length);
   if (ArgusRadsrsSerializeRecord(record, reader->sequence, &jsonseq,
                                  &jsonseq_length) < 0) {
      PyErr_SetFromErrno(PyExc_OSError);
      goto done;
   }

   payload = PyDict_New();
   if (payload == NULL)
      goto done;
   value = PyLong_FromUnsignedLong(reader->sequence);
   if ((value == NULL) || PyDict_SetItemString(payload, "sequence", value) < 0)
      goto done;
   Py_CLEAR(value);
   fidelity = ArgusRadsrsRecordFidelity(record, raw, raw_length);
   value = PyUnicode_FromString(fidelity);
   if ((value == NULL) || PyDict_SetItemString(payload, "fidelity", value) < 0)
      goto done;
   Py_CLEAR(value);
   if (have_raw)
      value = PyBytes_FromStringAndSize((const char *)raw, (Py_ssize_t)raw_length);
   else {
      value = Py_None;
      Py_INCREF(value);
   }
   if ((value == NULL) || PyDict_SetItemString(payload, "raw", value) < 0)
      goto done;
   Py_CLEAR(value);
   value = PyBytes_FromStringAndSize(jsonseq, (Py_ssize_t)jsonseq_length);
   if ((value == NULL) || PyDict_SetItemString(payload, "json_seq", value) < 0)
      goto done;
   Py_CLEAR(value);

   callback_result = PyObject_CallOneArg(reader->callback, payload);
   if (callback_result == NULL)
      goto done;
   Py_CLEAR(callback_result);
   reader->sequence++;
   reader->records++;
   result = 0;

done:
   Py_XDECREF(callback_result);
   Py_XDECREF(value);
   Py_XDECREF(payload);
   ArgusRadsrsFreeSerializedRecord(jsonseq);
   if (result < 0 && reader->parser != NULL)
      reader->parser->RaParseDone = 1;
   return result;
}

int
ArgusPythonReaderProcessRecord(struct ArgusParserStruct *parser,
                               struct ArgusRecordStruct *record)
{
   struct ArgusPythonReader *reader = ArgusPythonActiveReader;
   PyGILState_STATE gil_state;

   if ((reader == NULL) || (reader->parser != parser))
      return 0;
   gil_state = PyGILState_Ensure();
   if (reader->mode == ARGUS_PYTHON_READER_RECORDS)
      (void)ArgusPythonReaderDeliverRecord(reader, record);
   else if (reader->mode == ARGUS_PYTHON_READER_BATCHES)
      (void)ArgusPythonReaderAppendBatch(reader, record);
   PyGILState_Release(gil_state);
   return 1;
}

int
ArgusPythonReaderIsActive(void)
{
   return ArgusPythonActiveReader != NULL;
}

static struct ArgusPythonReader *
ArgusPythonReaderGet(PyObject *capsule)
{
   return (struct ArgusPythonReader *)PyCapsule_GetPointer(
      capsule, ARGUS_PYTHON_READER_CAPSULE);
}

static void
ArgusPythonReaderFreeSources(struct ArgusPythonReader *reader)
{
   struct ArgusPythonReaderSource *source = reader->sources;

   while (source != NULL) {
      struct ArgusPythonReaderSource *next = source->next;

      free(source->value);
      free(source);
      source = next;
   }
   reader->sources = NULL;
   reader->sources_tail = NULL;
}

static void
ArgusPythonReaderFinish(struct ArgusPythonReader *reader)
{
   struct ArgusParserStruct *parser = reader->parser;

   if (ArgusPythonActiveReader == reader)
      ArgusPythonActiveReader = NULL;
   Py_CLEAR(reader->callback);
   ArgusPythonReaderBatchClear(&reader->batch);
   if (parser != NULL) {
      free(parser->ArgusFilterCode.bf_insns);
      parser->ArgusFilterCode.bf_insns = NULL;
      free(parser->ArgusLocalFilter);
      parser->ArgusLocalFilter = NULL;
      ArgusCloseParser(parser);
      if (ArgusParser == parser)
         ArgusParser = NULL;
      reader->parser = NULL;
   }
   reader->mode = ARGUS_PYTHON_READER_IDLE;
}

static void
ArgusPythonReaderDestroy(struct ArgusPythonReader *reader)
{
   if (reader == NULL)
      return;
   ArgusPythonReaderFinish(reader);
   ArgusPythonReaderFreeSources(reader);
   free(reader->filter);
   free(reader);
}

static void
ArgusPythonReaderCapsuleDestructor(PyObject *capsule)
{
   struct ArgusPythonReader *reader = (struct ArgusPythonReader *)
      PyCapsule_GetPointer(capsule, ARGUS_PYTHON_READER_CAPSULE);

   if (reader != NULL)
      ArgusPythonReaderDestroy(reader);
   else
      PyErr_Clear();
}

static int
ArgusPythonReaderSetFilter(struct ArgusPythonReader *reader, const char *filter)
{
   char *copy;

   if (ArgusPythonActiveReader == reader) {
      PyErr_SetString(PyExc_RuntimeError,
                      "cannot change a filter while Reader.run() is active");
      return -1;
   }
   copy = strdup(filter != NULL ? filter : "");
   if (copy == NULL) {
      PyErr_NoMemory();
      return -1;
   }
   free(reader->filter);
   reader->filter = copy;
   return 0;
}

static int
ArgusPythonReaderAddSource(struct ArgusPythonReader *reader,
                           enum ArgusPythonReaderSourceType type,
                           const char *value)
{
   struct ArgusPythonReaderSource *source;

   if (reader->closed) {
      PyErr_SetString(PyExc_RuntimeError, "Reader is closed");
      return -1;
   }
   source = calloc(1, sizeof(*source));
   if (source == NULL) {
      PyErr_NoMemory();
      return -1;
   }
   if (value != NULL) {
      source->value = strdup(value);
      if (source->value == NULL) {
         free(source);
         PyErr_NoMemory();
         return -1;
      }
   }
   source->type = type;
   if (reader->sources_tail == NULL)
      reader->sources = source;
   else
      reader->sources_tail->next = source;
   reader->sources_tail = source;
   return 0;
}

static int
ArgusPythonReaderParseFields(PyObject *fields, unsigned int *field_mask)
{
   PyObject *sequence = NULL;
   Py_ssize_t index;
   Py_ssize_t length;
   unsigned int mask = 0;

   if ((fields == NULL) || (fields == Py_None)) {
      *field_mask = READER_FIELD_ALL;
      return 0;
   }
   sequence = PySequence_Fast(fields, "fields must be a sequence of field names");
   if (sequence == NULL)
      return -1;
   length = PySequence_Fast_GET_SIZE(sequence);
   for (index = 0; index < length; index++) {
      PyObject *item = PySequence_Fast_GET_ITEM(sequence, index);
      const char *name;

      if (!PyUnicode_Check(item)) {
         PyErr_SetString(PyExc_TypeError, "field names must be strings");
         goto failed;
      }
      name = PyUnicode_AsUTF8(item);
      if (name == NULL)
         goto failed;
      if (!strcmp(name, "sequence")) mask |= READER_FIELD_SEQUENCE;
      else if (!strcmp(name, "record_type")) mask |= READER_FIELD_RECORD_TYPE;
      else if (!strcmp(name, "version")) mask |= READER_FIELD_VERSION;
      else if (!strcmp(name, "start_time_ns")) mask |= READER_FIELD_START_TIME;
      else if (!strcmp(name, "end_time_ns")) mask |= READER_FIELD_END_TIME;
      else if (!strcmp(name, "flow_valid")) mask |= READER_FIELD_FLOW_VALID;
      else if (!strcmp(name, "src_addr")) mask |= READER_FIELD_SRC_ADDR;
      else if (!strcmp(name, "dst_addr")) mask |= READER_FIELD_DST_ADDR;
      else if (!strcmp(name, "protocol")) mask |= READER_FIELD_PROTOCOL;
      else if (!strcmp(name, "src_port")) mask |= READER_FIELD_SRC_PORT;
      else if (!strcmp(name, "dst_port")) mask |= READER_FIELD_DST_PORT;
      else if (!strcmp(name, "metrics_valid")) mask |= READER_FIELD_METRICS_VALID;
      else if (!strcmp(name, "src_packets")) mask |= READER_FIELD_SRC_PACKETS;
      else if (!strcmp(name, "dst_packets")) mask |= READER_FIELD_DST_PACKETS;
      else if (!strcmp(name, "src_bytes")) mask |= READER_FIELD_SRC_BYTES;
      else if (!strcmp(name, "dst_bytes")) mask |= READER_FIELD_DST_BYTES;
      else if (!strcmp(name, "raw")) mask |= READER_FIELD_RAW;
      else if (!strcmp(name, "fidelity")) mask |= READER_FIELD_FIDELITY;
      else {
         PyErr_Format(PyExc_ValueError, "unsupported batch field: %s", name);
         goto failed;
      }
   }
   Py_DECREF(sequence);
   *field_mask = mask;
   return 0;

failed:
   Py_DECREF(sequence);
   return -1;
}

static int
ArgusPythonReaderRejectCompressed(FILE *file, const char *path)
{
   unsigned char magic[6];
   size_t count;

   count = fread(magic, 1, sizeof(magic), file);
   if (ferror(file)) {
      PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
      return -1;
   }
   rewind(file);
   if ((count >= 2 && magic[0] == 0x1f &&
        (magic[1] == 0x8b || magic[1] == 0x9d)) ||
       (count >= 3 && magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h') ||
       (count >= 6 && magic[0] == 0xfd && magic[1] == 0x37 &&
        magic[2] == 0x7a && magic[3] == 0x58 && magic[4] == 0x5a &&
        magic[5] == 0x00)) {
      PyErr_SetString(PyExc_ValueError,
                      "compressed files are not supported by the in-process Reader");
      return -1;
   }
   return 0;
}

static int
ArgusPythonReaderRunFile(struct ArgusPythonReader *reader, const char *path,
                         int is_stdin)
{
   struct ArgusParserStruct *parser = reader->parser;
   struct ArgusFileInput file;
   struct ArgusInput *input;
   int fd;
   int read_status;
   int status = -1;

   memset(&file, 0, sizeof(file));
   file.filename = (char *)(is_stdin ? "-" : path);
   file.ostart = -1;
   file.ostop = -1;
   file.type = ARGUS_DATA_SOURCE;
   file.fd = -1;
   input = ArgusCalloc(1, sizeof(*input));
   if (input == NULL) {
      PyErr_NoMemory();
      return -1;
   }
   ArgusInputFromFile(input, &file);
   if (is_stdin) {
      /* Argus owns and closes input->file, so never pass it the host's stdin. */
      fd = dup(fileno(stdin));
      if (fd < 0) {
         PyErr_SetFromErrno(PyExc_OSError);
         goto done;
      }
      input->file = fdopen(fd, "rb");
      if (input->file == NULL) {
         int saved_errno = errno;

         close(fd);
         errno = saved_errno;
         PyErr_SetFromErrno(PyExc_OSError);
         goto done;
      }
   } else {
      input->file = fopen(path, "rb");
      if (input->file == NULL) {
         PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
         goto done;
      }
      if (ArgusPythonReaderRejectCompressed(input->file, path) < 0)
         goto done;
   }

   parser->ArgusCurrentInput = input;
   Py_BEGIN_ALLOW_THREADS
   read_status = ArgusReadConnection(parser, input, ARGUS_FILE);
   Py_END_ALLOW_THREADS
   if (read_status < 0) {
      PyErr_Format(PyExc_ValueError, "unable to read Argus input: %s", path);
      goto done;
   }
   parser->ArgusTotalMarRecords++;
   parser->ArgusTotalRecords++;
   ArgusHandleRecord(parser, input, &input->ArgusInitCon, 0,
                     &parser->ArgusFilterCode);
   if (PyErr_Occurred())
      goto done;
   Py_BEGIN_ALLOW_THREADS
   ArgusReadFileStream(parser, input);
   Py_END_ALLOW_THREADS
   status = PyErr_Occurred() ? -1 : 0;

done:
   RaArgusInputComplete(input);
   parser->ArgusCurrentInput = NULL;
   ArgusDeleteInput(parser, input);
   return status;
}

static void
ArgusPythonReaderDeleteQueueInputs(struct ArgusParserStruct *parser,
                                   struct ArgusQueueStruct *queue)
{
   struct ArgusInput *input;

   while ((input = (struct ArgusInput *)ArgusPopQueue(queue, ARGUS_LOCK)) != NULL)
      ArgusDeleteInput(parser, input);
}

static int
ArgusPythonReaderRunServerAttempt(struct ArgusPythonReader *reader,
                                  const char *server)
{
   struct ArgusParserStruct *parser = reader->parser;
   struct ArgusInput *input = NULL;
   int connection_status;
   int flags;
   int status = -1;

   if (!ArgusAddServerList(parser, (char *)server, ARGUS_DATA_SOURCE, IPPROTO_TCP)) {
      PyErr_Format(PyExc_ValueError, "unable to resolve Argus server: %s", server);
      return -1;
   }
   input = (struct ArgusInput *)ArgusPopQueue(parser->ArgusRemoteHosts, ARGUS_LOCK);
   if (input == NULL) {
      PyErr_Format(PyExc_ValueError, "unable to create Argus server input: %s", server);
      return -1;
   }
   Py_BEGIN_ALLOW_THREADS
   input->fd = ArgusGetServerSocket(input, 5);
   Py_END_ALLOW_THREADS
   if (input->fd < 0) {
      PyErr_SetFromErrno(PyExc_ConnectionError);
      goto done;
   }
   Py_BEGIN_ALLOW_THREADS
   connection_status = ArgusReadConnection(parser, input, ARGUS_SOCKET);
   Py_END_ALLOW_THREADS
   if (connection_status < 0) {
      if (connection_status == ARGUS_READ_CONNECTION_FILTER_REJECTED) {
         status = ARGUS_READ_CONNECTION_FILTER_REJECTED;
         PyErr_Format(PyExc_ConnectionError,
                      "Argus server rejected the remote filter: %s", server);
      } else {
         PyErr_Format(PyExc_ConnectionError,
                      "Argus server closed the connection: %s", server);
      }
      goto done;
   }
   flags = fcntl(input->fd, F_GETFL, 0L);
   if (flags < 0 || fcntl(input->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      PyErr_SetFromErrno(PyExc_OSError);
      goto done;
   }
   parser->ArgusTotalMarRecords++;
   parser->ArgusTotalRecords++;
   ArgusHandleRecord(parser, input, &input->ArgusInitCon, 0,
                     &parser->ArgusFilterCode);
   if (PyErr_Occurred())
      goto done;
   ArgusAddToQueue(parser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
   input = NULL;
   Py_BEGIN_ALLOW_THREADS
   ArgusReadStream(parser, parser->ArgusActiveHosts);
   Py_END_ALLOW_THREADS
   status = PyErr_Occurred() ? -1 : 0;

done:
   if (input != NULL)
      ArgusDeleteInput(parser, input);
   ArgusPythonReaderDeleteQueueInputs(parser, parser->ArgusActiveHosts);
   ArgusPythonReaderDeleteQueueInputs(parser, parser->ArgusRemoteHosts);
   parser->ArgusCurrentInput = NULL;
   return status;
}

static int
ArgusPythonReaderRunServer(struct ArgusPythonReader *reader, const char *server)
{
   struct ArgusParserStruct *parser = reader->parser;
   char *remote_filter;
   int status;

   status = ArgusPythonReaderRunServerAttempt(reader, server);
   if ((status != ARGUS_READ_CONNECTION_FILTER_REJECTED) ||
       (parser->ArgusRemoteFilter == NULL))
      return status;

   PyErr_Clear();
   remote_filter = parser->ArgusRemoteFilter;
   parser->ArgusRemoteFilter = NULL;
   free(remote_filter);
   parser->RaParseDone = 0;
   reader->remote_filter_fallback = 1;
   return ArgusPythonReaderRunServerAttempt(reader, server);
}

static int
ArgusPythonReaderBegin(struct ArgusPythonReader *reader, PyObject *callback,
                       enum ArgusPythonReaderMode mode)
{
   struct ArgusParserStruct *parser;
   char *filter;

   if (reader->closed) {
      PyErr_SetString(PyExc_RuntimeError, "Reader is closed");
      return -1;
   }
   if (ArgusPythonActiveReader != NULL || ArgusParser != NULL) {
      PyErr_SetString(PyExc_RuntimeError,
                      "only one Argus reader or legacy parser may be active");
      return -1;
   }
   if (!PyCallable_Check(callback)) {
      PyErr_SetString(PyExc_TypeError, "callback must be callable");
      return -1;
   }
   if (reader->sources == NULL) {
      PyErr_SetString(PyExc_ValueError, "Reader has no input sources");
      return -1;
   }
   if ((parser = ArgusNewParser("argusPython")) == NULL) {
      PyErr_NoMemory();
      return -1;
   }
   ArgusParser = parser;
   reader->parser = parser;
   parser->RaWriteOut = 0;
   parser->RaInitialized = 1;
   parser->uid = getuid();
   parser->pid = getpid();
   parser->ArgusGlobalTime = parser->ArgusRealTime;
   parser->ArgusFilterFiledes[0] = -1;
   parser->ArgusFilterFiledes[1] = -1;
   parser->ArgusControlFiledes[0] = -1;
   parser->ArgusControlFiledes[1] = -1;

   if (reader->filter[0] != '\0') {
      parser->ArgusLocalFilter = strdup(reader->filter);
      parser->ArgusRemoteFilter = strdup(reader->filter);
      if ((parser->ArgusLocalFilter == NULL) || (parser->ArgusRemoteFilter == NULL)) {
         PyErr_NoMemory();
         return -1;
      }
      filter = strdup(reader->filter);
      if (filter == NULL) {
         PyErr_NoMemory();
         return -1;
      }
      if (ArgusFilterCompile(&parser->ArgusFilterCode, filter, parser->Oflag) < 0) {
         free(filter);
         PyErr_SetString(PyExc_ValueError, "invalid Argus filter expression");
         return -1;
      }
      free(filter);
   }
   if (mode == ARGUS_PYTHON_READER_BATCHES &&
       ArgusPythonReaderBatchReset(reader) < 0)
      return -1;
   reader->sequence = 0;
   reader->records = 0;
   reader->remote_filter_fallback = 0;
   reader->mode = mode;
   reader->callback = callback;
   Py_INCREF(callback);
   ArgusPythonActiveReader = reader;
   return 0;
}

static PyObject *
ArgusPythonReaderRun(struct ArgusPythonReader *reader, PyObject *callback,
                     enum ArgusPythonReaderMode mode)
{
   struct ArgusPythonReaderSource *source;
   unsigned long records;
   int status = 0;

   if (ArgusPythonReaderBegin(reader, callback, mode) < 0) {
      ArgusPythonReaderFinish(reader);
      return NULL;
   }
   for (source = reader->sources; source != NULL && status == 0;
        source = source->next) {
      if (source->type == ARGUS_PYTHON_SOURCE_FILE)
         status = ArgusPythonReaderRunFile(reader, source->value, 0);
      else if (source->type == ARGUS_PYTHON_SOURCE_STDIN)
         status = ArgusPythonReaderRunFile(reader, "-", 1);
      else
         status = ArgusPythonReaderRunServer(reader, source->value);
      if (reader->parser != NULL && !PyErr_Occurred())
         reader->parser->RaParseDone = 0;
   }
   if (status == 0 && mode == ARGUS_PYTHON_READER_BATCHES)
      status = ArgusPythonReaderFlushBatch(reader);
   records = reader->records;
   ArgusPythonReaderFinish(reader);
   if (status < 0 || PyErr_Occurred())
      return NULL;
   return PyLong_FromUnsignedLong(records);
}

PyObject *
argus_reader_open(char *filter, PyObject *fields, unsigned long batch_size,
                  unsigned long max_bytes)
{
   struct ArgusPythonReader *reader;
   PyObject *capsule;

   if (batch_size == 0)
      batch_size = ARGUS_PYTHON_DEFAULT_BATCH_SIZE;
   if (max_bytes == 0)
      max_bytes = ARGUS_PYTHON_DEFAULT_MAX_BYTES;
   if (batch_size > (unsigned long)PY_SSIZE_T_MAX ||
       max_bytes > (unsigned long)PY_SSIZE_T_MAX) {
      PyErr_SetString(PyExc_OverflowError, "batch_size or max_bytes is too large");
      return NULL;
   }
   reader = calloc(1, sizeof(*reader));
   if (reader == NULL) {
      PyErr_NoMemory();
      return NULL;
   }
   reader->batch_size = batch_size;
   reader->max_bytes = max_bytes;
   if (ArgusPythonReaderParseFields(fields, &reader->fields) < 0)
      goto failed;
   if (ArgusPythonReaderSetFilter(reader, filter) < 0)
      goto failed;
   capsule = PyCapsule_New(reader, ARGUS_PYTHON_READER_CAPSULE,
                           ArgusPythonReaderCapsuleDestructor);
   if (capsule == NULL)
      goto failed;
   return capsule;

failed:
   ArgusPythonReaderDestroy(reader);
   return NULL;
}

int
argus_reader_close(PyObject *capsule)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   if (ArgusPythonActiveReader == reader) {
      PyErr_SetString(PyExc_RuntimeError, "cannot close Reader while it is active");
      return -1;
   }
   if (!reader->closed) {
      ArgusPythonReaderFreeSources(reader);
      free(reader->filter);
      reader->filter = NULL;
      reader->closed = 1;
   }
   return 0;
}

int
argus_reader_set_filter(PyObject *capsule, char *filter)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   if (reader->closed) {
      PyErr_SetString(PyExc_RuntimeError, "Reader is closed");
      return -1;
   }
   return ArgusPythonReaderSetFilter(reader, filter);
}

int
argus_reader_add_file(PyObject *capsule, char *path)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   if ((path == NULL) || (path[0] == '\0')) {
      PyErr_SetString(PyExc_ValueError, "file path must not be empty");
      return -1;
   }
   return ArgusPythonReaderAddSource(reader, ARGUS_PYTHON_SOURCE_FILE, path);
}

int
argus_reader_add_stdin(PyObject *capsule)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   return ArgusPythonReaderAddSource(reader, ARGUS_PYTHON_SOURCE_STDIN, NULL);
}

int
argus_reader_add_server(PyObject *capsule, char *server)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   if ((server == NULL) || (server[0] == '\0')) {
      PyErr_SetString(PyExc_ValueError, "server must not be empty");
      return -1;
   }
   return ArgusPythonReaderAddSource(reader, ARGUS_PYTHON_SOURCE_SERVER, server);
}

PyObject *
argus_reader_run(PyObject *capsule, PyObject *callback)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return NULL;
   return ArgusPythonReaderRun(reader, callback, ARGUS_PYTHON_READER_RECORDS);
}

PyObject *
argus_reader_run_batches(PyObject *capsule, PyObject *callback)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return NULL;
   return ArgusPythonReaderRun(reader, callback, ARGUS_PYTHON_READER_BATCHES);
}

int
argus_reader_remote_filter_fallback(PyObject *capsule)
{
   struct ArgusPythonReader *reader = ArgusPythonReaderGet(capsule);

   if (reader == NULL)
      return -1;
   return reader->remote_filter_fallback;
}
