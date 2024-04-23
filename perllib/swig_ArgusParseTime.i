%module "qosient::XS::util"

%include "typemaps.i"
%apply int *OUTPUT { int *start, int *end };

%{
extern int swig_ArgusParseTime (char *time_string, int *start, int *end);
%}

/* newer versions of swig use the %rename directive */
%name(ArgusParseTime) extern int swig_ArgusParseTime (char *time_string, int *start, int *end);
