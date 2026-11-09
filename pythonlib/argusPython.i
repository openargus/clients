%module argusPython

%include "typemaps.i"
%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#define PY_ARRAY_UNIQUE_SYMBOL ARGUS_PYTHON_ARRAY_API
#include "argusPython.h"
#include "argusPython_reader.h"
int argusInit (void);
int readArgusData (char *datafile);
int setArgusSchema (char *titles);
int setArgusBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);
PyObject *argus_reader_open(char *filter, PyObject *fields, unsigned long batch_size, unsigned long max_bytes);
int argus_reader_close(PyObject *reader);
int argus_reader_set_filter(PyObject *reader, char *filter);
int argus_reader_add_file(PyObject *reader, char *path);
int argus_reader_add_stdin(PyObject *reader);
int argus_reader_add_server(PyObject *reader, char *server);
PyObject *argus_reader_run(PyObject *reader, PyObject *callback);
PyObject *argus_reader_run_batches(PyObject *reader, PyObject *callback);
int argus_reader_remote_filter_fallback(PyObject *reader);
%}

%include "numpy.i"

%init %{
    if (_import_array() < 0)
        return -1;
%}

%exception {
    $action
    if (PyErr_Occurred())
        SWIG_fail;
}

int argusInit (void);
int readArgusData (char *datafile);
int setArgusSchema (char *titles);
int setArgusBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);

%rename(_argus_reader_open) argus_reader_open;
%rename(_argus_reader_close) argus_reader_close;
%rename(_argus_reader_set_filter) argus_reader_set_filter;
%rename(_argus_reader_add_file) argus_reader_add_file;
%rename(_argus_reader_add_stdin) argus_reader_add_stdin;
%rename(_argus_reader_add_server) argus_reader_add_server;
%rename(_argus_reader_run) argus_reader_run;
%rename(_argus_reader_run_batches) argus_reader_run_batches;
%rename(_argus_reader_remote_filter_fallback) argus_reader_remote_filter_fallback;

PyObject *argus_reader_open(char *filter, PyObject *fields, unsigned long batch_size, unsigned long max_bytes);
int argus_reader_close(PyObject *reader);
int argus_reader_set_filter(PyObject *reader, char *filter);
int argus_reader_add_file(PyObject *reader, char *path);
int argus_reader_add_stdin(PyObject *reader);
int argus_reader_add_server(PyObject *reader, char *server);
PyObject *argus_reader_run(PyObject *reader, PyObject *callback);
PyObject *argus_reader_run_batches(PyObject *reader, PyObject *callback);
int argus_reader_remote_filter_fallback(PyObject *reader);

%pythoncode %{
import warnings as _warnings

_legacy_argus_critic = argus_critic
_legacy_argus_match = argus_match

def argus_critic(y_true, y_pred):
    _warnings.warn(
        "argus_critic() is deprecated; use Reader.run_batches() for native Argus input",
        DeprecationWarning,
        stacklevel=2,
    )
    return _legacy_argus_critic(y_true, y_pred)

def argus_match(y_true):
    _warnings.warn(
        "argus_match() is deprecated; use Reader.run_batches() for native Argus input",
        DeprecationWarning,
        stacklevel=2,
    )
    return _legacy_argus_match(y_true)

class Record:
    """An owned native Argus record and its exact radsrs JSON text sequence."""

    __slots__ = ("sequence", "fidelity", "raw", "json_seq")

    def __init__(self, sequence, fidelity, raw, json_seq):
        self.sequence = sequence
        self.fidelity = fidelity
        self.raw = raw
        self.json_seq = json_seq

    @classmethod
    def _from_native(cls, payload):
        return cls(
            payload["sequence"],
            payload["fidelity"],
            payload["raw"],
            payload["json_seq"],
        )

class RecordBatch:
    """A bounded, columnar batch with NumPy arrays and raw byte offsets."""

    schema = "argus.python/1"
    fidelity_labels = (
        "no_raw",
        "exact_native_v3_v5",
        "derived_current_format",
        "derived_or_legacy",
    )

    def __init__(self, columns, count):
        self.columns = columns
        self.count = count

    def raw(self, index):
        offsets = self.columns["raw_offsets"]
        data = self.columns["raw_data"]
        return memoryview(data[offsets[index]:offsets[index + 1]])

class Reader:
    """Single-process native Argus reader for streaming records or NumPy batches."""

    default_fields = (
        "sequence", "record_type", "version", "start_time_ns", "end_time_ns",
        "flow_valid", "src_addr", "dst_addr", "protocol", "src_port", "dst_port",
        "metrics_valid", "src_packets", "dst_packets", "src_bytes", "dst_bytes",
        "raw", "fidelity",
    )

    def __init__(self, filter="", fields=None, batch_size=65536, max_bytes=8 * 1024 * 1024):
        if fields is None:
            fields = self.default_fields
        elif isinstance(fields, str):
            fields = (fields,)
        self._reader = _argus_reader_open(filter or "", fields, batch_size, max_bytes)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def close(self):
        if self._reader is not None:
            _argus_reader_close(self._reader)
            self._reader = None

    def set_filter(self, expression):
        _argus_reader_set_filter(self._reader, expression or "")
        return self

    def add_file(self, path):
        _argus_reader_add_file(self._reader, path)
        return self

    def add_stdin(self):
        _argus_reader_add_stdin(self._reader)
        return self

    def add_server(self, server):
        _argus_reader_add_server(self._reader, server)
        return self

    @property
    def remote_filter_fallback(self):
        return bool(_argus_reader_remote_filter_fallback(self._reader))

    def run(self, callback):
        def deliver(payload):
            return callback(Record._from_native(payload))
        return _argus_reader_run(self._reader, deliver)

    stream = run

    def run_batches(self, callback):
        def deliver(payload):
            columns, count = payload
            return callback(RecordBatch(columns, count))
        return _argus_reader_run_batches(self._reader, deliver)

    batches = run_batches
%}
