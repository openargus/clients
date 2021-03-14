%module argustime

%{
#define SWIG_FILE_WITH_INIT
#include "argustime.h"
%}

int argustime (char *time_string, int *start, int *end);
