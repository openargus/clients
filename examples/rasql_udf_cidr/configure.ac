# Require a somewhat recent version of autoconf
AC_PREREQ(2.59)

# Set up package name, version, and bug-reports email
# These can later be referenced in the code as PACKAGE_VERSION,... and
# in the Makefile.am as VERSION
#
AC_INIT(rasql_udf_cidr, 0.5, carter@qosient.com)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)

# Initialize automake
AM_INIT_AUTOMAKE

# We need the libtool program
#
AC_PROG_LIBTOOL

# I need a C compiler; C++ projects should use:  AC_PROG_CPP
#
AC_PROG_CC

# Require the mysql library.  This uses the ax_lib_mysql.m4
# file to look for the mysql_config program and then run it in order
# to set up MYSQL_CFLAGS and MYSQL_LDFLAGS
#
AX_LIB_MYSQL(,,AC_MSG_ERROR("Can't find mysql library" ))

AC_CHECK_LIB(dl,dlopen,AC_DEFINE(HAVE_DLOPEN,1,[Have dlopen()]))

AC_C_CONST
AC_TYPE_SIZE_T

# Output from the configure script into Makefile
#
AC_OUTPUT(Makefile)
