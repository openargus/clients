%module argusWgan

%include "typemaps.i"
%apply int *OUTPUT {int *start, int *end};

%{
#define SWIG_FILE_WITH_INIT
#include "argusWgan.h"
int setSchema (char *titles);
int argus_critic (char *fields);

int argustime (char *time_string, int *start, int *end);
%}

int setSchema (char *titles);
int argus_critic (char *fields);
int argustime (char *time_string, int *start, int *end);
