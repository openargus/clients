/*
 * Argus Python reader API.
 */

#ifndef ARGUS_PYTHON_READER_H
#define ARGUS_PYTHON_READER_H

#include <Python.h>

struct ArgusParserStruct;
struct ArgusRecordStruct;

int ArgusPythonReaderProcessRecord(struct ArgusParserStruct *parser,
                                   struct ArgusRecordStruct *record);
int ArgusPythonReaderIsActive(void);

PyObject *argus_reader_open(char *filter, PyObject *fields,
                            unsigned long batch_size,
                            unsigned long max_bytes);
int argus_reader_close(PyObject *reader);
int argus_reader_set_filter(PyObject *reader, char *filter);
int argus_reader_add_file(PyObject *reader, char *path);
int argus_reader_add_stdin(PyObject *reader);
int argus_reader_add_server(PyObject *reader, char *server);
PyObject *argus_reader_run(PyObject *reader, PyObject *callback);
PyObject *argus_reader_run_batches(PyObject *reader, PyObject *callback);
int argus_reader_remote_filter_fallback(PyObject *reader);

#endif
