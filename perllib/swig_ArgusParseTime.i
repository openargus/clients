%module "qosient::XS::util"

%include "typemaps.i"
%apply int *OUTPUT { int *start, int *end };

%{
extern int swig_ArgusParseTime (char *time_string, int *start, int *end);
%}

/* assume using newer versions of swig ... use the %rename directive */
%rename(ArgusParseTime) swig_ArgusParseTime;
extern int swig_ArgusParseTime (char *time_string, int *start, int *end);
