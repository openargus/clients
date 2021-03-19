%module argusWgan

%include "typemaps.i"

%typemap(in) (TF_Tensor *y_pred, TF_Tensor *y_true) {
}

%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#include "argusWgan.h"

int setSchema (char *titles);
TF_Tensor *argus_critic (TF_Tensor *y_pred, TF_Tensor *y_true);
int argustime (char *time_string, int *start, int *end);
%}

%include "argusWgan.h"
int setSchema (char *titles);
TF_Tensor *argus_critic (TF_Tensor *y_pred, TF_Tensor *y_true);
int argustime (char *time_string, int *start, int *end);
