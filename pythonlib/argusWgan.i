%module argusWgan

%include "typemaps.i"
%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#include "argusWgan.h"
int setSchema (char *titles);
int setBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);
%}

%include "numpy.i"

%init %{
    import_array();
%}

int setSchema (char *titles);
int setBaseline (char *baseline);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
PyObject *argus_match (PyObject *y_true);
int argustime (char *time_string, int *start, int *end);
