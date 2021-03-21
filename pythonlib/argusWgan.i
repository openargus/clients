%module argusWgan

%include "typemaps.i"
%include "numpy.i"

%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#include "argusWgan.h"

int setSchema (char *titles);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
int argustime (char *time_string, int *start, int *end);
%}

%include "argusWgan.h"
int setSchema (char *titles);
PyObject *argus_critic (PyObject *y_true, PyObject *y_pred);
int argustime (char *time_string, int *start, int *end);
