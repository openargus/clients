%module argusWgan

%{
#define SWIG_FILE_WITH_INIT
#include "argusWgan.h"
%}

int argusWgan (char *time_string, int *start, int *end);
