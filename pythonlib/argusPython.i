%module argusPython

%include "typemaps.i"
%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#include "argusPython.h"
int argusInit (void);
int readArgusData (char *datafile);
int setArgusSchema (char *titles);
int setArgusBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);
%}

%include "numpy.i"

%init %{
    import_array();
%}

int argusInit (void);
int readArgusData (char *datafile);
int setArgusSchema (char *titles);
int setArgusBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);
