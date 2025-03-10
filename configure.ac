# 
#  Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2024 QoSient, LLC
#  All rights reserved.
# 
#  This program is free software, released under the GNU General
#  Public License; you can redistribute it and/or modify it under the terms
#  of the GNU General Public License as published by the Free Software
#  Foundation; either version 3, or any later version.
#
#  Other licenses are available through QoSient, LLC.
#  Inquire at info@qosient.com.
#
#  This program is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the * GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# 
#  $Id: //depot/gargoyle/clients/configure.ac#28 $
#  $DateTime: 2016/10/10 23:14:45 $
#  $Change: 3219 $
#
#
# Process this file with autoconf to produce a configure script.

m4_include([m4/python.m4])


AC_PREREQ([2.69])
AC_INIT([Argus-5.0 Client Programs],[5.0],[bug-report@qosient.com],[argus-clients],[http://qosient.com/argus])
PACKAGE_RELEASE='3.6'
AC_CONFIG_MACRO_DIR([./m4])
AC_CONFIG_SRCDIR([clients/ra.c])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS([include/argus_config.h])
AC_CANONICAL_TARGET

AC_LBL_C_INIT(V_CCOPT, V_INCLS)

# Checks for programs.
AC_PROG_LN_S
AC_PROG_LEX(noyywrap)
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_YACC

AC_CHECK_PROGS(V_RANLIB, ranlib, @true)
AC_QOSIENT_LEX_AND_YACC(V_LEX, V_YACC, argus_)

# Checks for libraries.
AC_QOSIENT_READLINE(V_READLINE, V_READLINE_INCLS)

CMU_SASL2(V_INCLS)
AC_CMU_MYSQL

AC_CHECK_HEADERS(zlib.h, [AC_CHECK_LIB(z, uncompress, ZLIB="-lz")])
AC_CHECK_HEADERS(dns_sd.h, [AC_CHECK_LIB(dns_sd, DNSServiceRegister, DNSLIB="-ldns_sd")])
AC_QOSIENT_FLOWTOOLS(V_FLOWTOOLS, V_INCLS)

if test ! -z "$V_FLOWTOOLS"; then
   AC_DEFINE([ARGUS_FLOWTOOLS], [], [Using Flow Tools library])
   if test -f "$V_FLOWTOOLS"; then
      if test -f lib/libft.a; then
         rm -rf lib/libft.a
      fi
      ftdir=`echo $V_FLOWTOOLS | sed -e 's/\.\./..\/../'`
      V_FTDEP=$ftdir
   else
      if test "$V_FLOWTOOLS" = "-lft" ; then
         if test -f lib/libft.a; then
            rm -rf lib/libft.a
         fi
      fi
   fi
fi

AC_QOSIENT_PCRE(V_PCRE, V_INCLS)
if test ! -z "$V_PCRE"; then
   if test -f "$V_PCRE"; then
      if test -f lib/libpcre.a; then
         rm -rf lib/libpcre.a
      fi
      pcredir=`echo $V_PCRE | sed -e 's/\.\./..\/../'`
   fi
   LIBS="$LIBS $V_PCRE"
fi

# Checks for header files.
AC_HEADER_DIRENT
AC_PROG_EGREP

AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS([sys/types.h sys/sockio.h sys/file.h string.h fcntl.h syslog.h stdbool.h])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h libintl.h malloc.h memory.h netdb.h netinet/in.h net/if_dl.h])
AC_CHECK_HEADERS([stdlib.h stddef.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h])

AC_CHECK_HEADERS([sys/mount.h sys/time.h sys/vfs.h syslog.h termios.h unistd.h values.h ifaddrs.h dns_sd.h])
AC_CHECK_HEADERS([uuid/uuid.h linux/uuid.h uuid.h])
AC_CHECK_HEADERS([sys/systm.h])
AC_CHECK_HEADERS([arpa/nameser.h])
AC_CHECK_HEADERS([arpa/nameser_compat.h])
AC_CHECK_HEADERS([stdbool.h])

saved_CPPFLAGS=$CPPFLAGS

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AC_SYS_LARGEFILE
AC_LBL_UNALIGNED_ACCESS

AC_LBL_DEVEL(V_CCOPT)
AC_QOSIENT_DEBUG(V_CCOPT)
AC_QOSIENT_MEMORY

AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_CHECK_HEADERS_ONCE([sys/time.h])

AC_STRUCT_TM
AC_STRUCT_TIMEZONE

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_VPRINTF
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_STRTOD


AC_CHECK_FUNCS(backtrace)
AC_CHECK_FUNCS(openlog syslog)
AC_CHECK_FUNCS(vfprintf strlcpy)
AC_CHECK_FUNCS(strftime)
AC_CHECK_FUNCS(inet_aton)
AC_CHECK_FUNCS(setlinebuf)
AC_CHECK_FUNCS(strerror strtof)
AC_CHECK_FUNCS(floorf remainderf)
AC_CHECK_FUNCS(timegm)
AC_CHECK_FUNCS(isatty)

needsnprintf=no
AC_CHECK_FUNCS(vsnprintf snprintf,, [needsnprintf=yes])
if test $needsnprintf = yes; then
   AC_LIBOBJ(snprintf)
fi
#
# Do this before checking for ether_hostton(), as it's a
# "gethostbyname() -ish function".
#
AC_LBL_LIBRARY_NET

AC_CHECK_FUNCS([ether_hostton getaddrinfo gethostname])
AC_CHECK_FUNCS([alarm bzero endgrent endpwent floor gethostbyaddr gethostbyname getpass gettimeofday inet_ntoa isascii localtime_r])
AC_CHECK_FUNCS([memchr memmove memset mkdir modf pow putenv realpath regcomp select setenv socket sqrt strcasecmp strchr])
AC_CHECK_FUNCS([strdup strerror strlcat strncasecmp strpbrk strerror strrchr strstr strtol strtof srandomdev tzset])
AC_CHECK_FUNCS([gethostuuid])
AC_CHECK_FUNCS([posix_memalign memalign])

AC_SEARCH_LIBS([clock_gettime], [rt], [
    AC_DEFINE(HAVE_CLOCK_GETTIME, 1,[Have clock_gettime])
])
AC_SEARCH_LIBS([clock_nanosleep], [rt], [
    AC_DEFINE(HAVE_CLOCK_NANOSLEEP, 1,[Have clock_nanosleep])
])

case "$target_os" in
   *) COMPATLIB="-lm"
esac

AC_QOSIENT_THREADS(V_THREADS)

#AC_QOSIENT_TCPWRAP(V_WRAPDEP, V_INCLS)
#if test ! -z "$V_WRAPDEP"; then
#   if test -f "$V_WRAPDEP"; then
#      if test -f lib/libwrap.a; then
#         rm -rf lib/libwrap.a
#      fi
#      wrapdir=`echo $V_WRAPDEP | sed -e 's/^\.\./..\/../'`
#      ln -s $wrapdir lib/libwrap.a
#      V_WRAPDEP="../lib/libwrap.a"
#   else
#      if test "$V_WRAPDEP" = "-lwrap" ; then
#         if test -f lib/libwrap.a; then
#            rm -rf lib/libwrap.a
#         fi
#         case "$target_os" in
#         linux*)
#            V_WRAPDEP="$V_WRAPDEP -lnsl";;
#         esac
#      fi
#   fi
#   AC_DEFINE([HAVE_TCP_WRAPPER], [], [Using Tcp wrappers])
#   WRAPLIBS="$V_WRAPDEP"
#fi

saved_CPPFLAGS=$CPPFLAGS
saved_LIBS=$LIBS
LIB_XDR=""

AC_CHECK_HEADERS([rpc/xdr.h], ,
   [CPPFLAGS="${saved_CPPFLAGS} -I/usr/include/tirpc"
    unset ac_cv_header_rpc_xdr_h
    AC_CHECK_HEADERS(rpc/xdr.h,
      [XDR_INCLS="-I/usr/include/tirpc"
      LIB_XDR="-ltirpc"])],
      [#include <rpc/types.h>
       #include <rpc/xdr.h>])

LIBS="$LIB_XDR $LIBS"

AC_CHECK_FUNCS(xdrmem_create,
   AC_DEFINE([HAVE_XDR], [], [Using system XDR library]),
   LIB_XDR=""
   XDR_INCLS=""
   )

CPPFLAGS=${saved_CPPFLAGS}
LIBS=${saved_LIBS}


CURSESLIB=""
saved_CPPFLAGS=$CPPFLAGS
saved_LDFLAGS=$LDFLAGS
saved_LIBS=$LIBS

case "$target_os" in
   cygwin*)
      NCURSES_INCLS="-I/usr/include/ncurses"
      NCURSES_LDFLAGS="-L/usr/lib"
      CPPFLAGS="${saved_CPPFLAGS} ${NCURSES_INCLS}"
      LDFLAGS="${saved_LDFLAGS} ${NCURSES_LDFLAGS}"

      AC_CHECK_HEADERS(ncurses.h, CURSESLIB="-lncurses",
         [AC_CHECK_HEADERS(curses.h, CURSESLIB="-lcurses")],)

      if test "$CURSESLIB" = "-lncurses"; then
         AC_CHECK_LIB(ncurses, initscr,
           [AC_DEFINE([ARGUS_CURSES], [], [Using ncurses])
            CURSES_INCLS="-I/usr/include/ncurses"
            LIBS="$LIBS -L/usr/lib" ],)
      else
         if test "$CURSESLIB" = "-lcurses"; then
            AC_DEFINE([ARGUS_CURSES], [], [Using curses])
         fi
      fi

      CPPFLAGS="${saved_CPPFLAGS}"
      LDFLAGS="${saved_LDFLAGS}"
      ;;

   solaris*)
      NCURSES_INCLS="-I/usr/include/ncurses"
      NCURSES_LDFLAGS="-L/usr/gnu/lib"
      CPPFLAGS="${saved_CPPFLAGS} ${NCURSES_INCLS}"
      LDFLAGS="${saved_LDFLAGS} ${NCURSES_LDFLAGS}"

      AC_CHECK_HEADERS(ncurses.h, CURSESLIB="-lncurses",
         [AC_CHECK_HEADERS(curses.h, CURSESLIB="-lcurses")],)

      if test "$CURSESLIB" = "-lncurses"; then
         AC_CHECK_LIB(ncurses, initscr,
           [AC_DEFINE([ARGUS_CURSES], [], [Using ncurses])
            CURSES_INCLS="-I/usr/include/ncurses"
            LIBS="$LIBS -L/usr/gnu/lib" ],)
      else
         if test "$CURSESLIB" = "-lcurses"; then
            AC_DEFINE([ARGUS_CURSES], [], [Using curses])
         fi
      fi

      CPPFLAGS="${saved_CPPFLAGS}"
      LDFLAGS="${saved_LDFLAGS}"
      ;;

   *)
      AC_CHECK_HEADERS(ncurses.h, [AC_CHECK_LIB(ncurses, initscr,
           CURSESLIB="-lncurses")],
           [AC_CHECK_HEADERS(curses.h, AC_CHECK_LIB(curses, initscr,
                   CURSESLIB="-lcurses"))
           ],)

      if test "$CURSESLIB" = "-lncurses"; then
         AC_DEFINE([ARGUS_CURSES], [], [Using ncurses])
      else
         if test "$CURSESLIB" = "-lcurses"; then
            AC_DEFINE([ARGUS_CURSES], [], [Using curses])
         fi
      fi
      ;;
esac



case "$target_cpu" in
*86)
   have_x86=yes;
   ;;

powerpc-apple*)
   ;;
        
powerpc64-*-linux-gnu)
   V_CCOPT="$V_CCOPT -m64 -fPIC"
   ;;   
        
esac    

case "$target_os" in

aix*)
	dnl Workaround to enable certain features
	have_sun=yes;
	;;

darwin*)
	have_darwin=yes;
	saved_LDFLAGS=$LDFLAGS
	LDFLAGS="${saved_LDFLAGS} -Wlinker -rpath /usr/local/mysql/lib"
	;;

hpux9*)
        have_hpux_nine=yes;
	;;

hpux10.0*)
	;;

hpux10.1*)
	;;

hpux*)
	dnl HPUX 10.20 and above is similar to HPUX 9...
	have_hpux_ten=yes;
	;;

sinix*)
	AC_MSG_CHECKING(if SINIX compiler defines sinix)
	AC_CACHE_VAL(ac_cv_cc_sinix_defined,
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[int i = sinix;]])],[ac_cv_cc_sinix_defined=yes],[ac_cv_cc_sinix_defined=no]))
	    AC_MSG_RESULT($ac_cv_cc_sinix_defined)
	    if test "$ac_cv_cc_sinix_defined" = "no" ; then
               AC_DEFINE([sinix], [], [Description])
	    fi
	;;

solaris*)
	AC_DEFINE(ARGUS_SOLARIS,1,[On solaris])
	AC_MSG_CHECKING(for LD_LIBRARY_PATH, since you appear to be running Solaris)
	if test "x$LD_LIBRARY_PATH" != "x" ; then
		LIBS="$LIBS -R$LD_LIBRARY_PATH"
		AC_MSG_RESULT(yes -- added LD_LIBRARY_PATH to run-time linker path)
	else
		AC_MSG_RESULT(no -- this may be a problem in a few seconds)
	fi
	COMPATLIB="-lsocket -lnsl -lrt $COMPATLIB"
	;;

linux*)
	;;

cygwin*)
	have_cygwin=yes;
	V_INCLS="$V_INCLS -I../include/cygwin-include"
	;;
esac

if test "$have_x86" = yes ; then
   AC_DEFINE([CONFIG_X86_BSWAP], [], [System has x86 endian support])
fi
if test "$have_darwin" = yes ; then
   AC_DEFINE([HAVE_DARWIN], [], [Mac OS X])
fi
if test "$have_hpux_nine" = yes ; then
   AC_DEFINE([HAVE_HPUX9], [], [HPUX 9])
fi
if test "$have_hpux_ten" = yes ; then
   AC_DEFINE([HAVE_HPUX10_20], [], [HPUX 10])
fi
if test "$have_sun" = yes ; then
   AC_DEFINE([_SUN], [], [Description])
fi
if test "$have_cygwin" = yes ; then
   AC_DEFINE([CYGWIN], [], [Using cygwin])
fi

AC_QOSIENT_LIBMAXMINDDB
if test "x$LIBMAXMINDDB_LIBS" = "x"; then
   AC_QOSIENT_GEOIP(V_GEOIPDEP, V_INCLS)
fi

AC_CACHE_CHECK([tm_gmtoff in struct tm], tcl_cv_member_tm_gmtoff, [
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <time.h>]], [[struct tm tm; tm.tm_gmtoff;]])],[tcl_cv_member_tm_gmtoff=yes],[tcl_cv_member_tm_gmtoff=no])])
if test $tcl_cv_member_tm_gmtoff = yes ; then
   AC_DEFINE([HAVE_TM_GMTOFF], [], [tm_gmtoff in struct tm])
fi

AC_CACHE_CHECK([sys_errlist in stdio.h], arg_cv_sys_errlist, [
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[char *ptr = sys_errlist[0];]])],[arg_cv_sys_errlist=yes],[arg_cv_sys_errlist=no])])
if test $arg_cv_sys_errlist = yes ; then
   AC_DEFINE([ARGUS_SYS_ERRLIST], [], [sys_errlist in stdio.h])
fi

if test "$V_FLOWTOOLS" = "-lft" ; then
   LIBS="$LIBS $V_FLOWTOOLS"
fi

INSTALL_LIB="../lib"
INSTALL_BIN="../bin"

DIRS="./common ./include ./clients"

if test "$with_examples" != no; then
   DIRS="$DIRS ./examples"
fi

if test "$with_perllib" != no; then
   DIRS="$DIRS ./perllib"
fi    

if test "$with_pythonlib" != no; then
   DIRS="$DIRS ./pythonlib"
fi    

if test "$with_pluribus" != no; then
   AC_DEFINE([ARGUS_PLURIBUS], [], [Building for pluribus])
fi

V_INCLS_EXAMPLES=`echo $V_INCLS | sed -e 's/\.\./..\/../'`

# from https://www.freedesktop.org/software/systemd/man/daemon.html

PKG_PROG_PKG_CONFIG

if test -d "/usr/lib/systemd"; then
  if test -n "$PKG_CONFIG"; then
  AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
  AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
  AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
  fi
fi

LIBCURL_CHECK_CONFIG
AC_QOSIENT_CURLEXE
AC_QOSIENT_LIBUUID
AC_QOSIENT_MACHINE_ID

AC_QOSIENT_LIBCARES

#
# Perl stuff
#

AX_PERL_EXT
if test x"$PERL" = x; then
    AC_MSG_ERROR("cannot find Perl")
fi
V_PERL=$PERL
 
PERL_CFLAGS=`perl -MExtUtils::Embed -e ccopts`
PERL_LDFLAGS=`perl -MExtUtils::Embed -e ldopts`
 
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="${saved_CPPFLAGS} ${PERL_CFLAGS}"
AC_CHECK_HEADERS(EXTERN.h)
CPPFLAGS="${saved_CPPFLAGS}"

#
# Python stuff
#

case "$target_os" in 
darwin*)
        am_cv_python_inc="/Library/Frameworks/Python.framework/Versions/"$PYTHON_VERSION"/include/python"$PYTHON_VERSION
        ;;
*) 
        am_cv_python_inc="/usr/include/python"$PYTHON_VERSION
        ;;
esac
 
V_PYTHON_INCLS="-I"$am_cv_python_inc
CPPFLAGS="${saved_CPPFLAGS} ${V_PYTHON_INCLS}"
AC_CHECK_HEADERS(Python.h)
CPPFLAGS="${saved_CPPFLAGS}"

AC_ARG_ENABLE(python,
   AS_HELP_STRING([--disable-python], [Disable scripts that depends on python]),
   [case "${enableval}" in
          yes) HAVE_PYTHON=yes ;;
          no)  HAVE_PYTHON=no ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-python]) ;;
   esac],[HAVE_PYTHON=yes])

if test "x$HAVE_PYTHON" = "xyes" ; then
   AM_PATH_PYTHON([3],, [:])
   AM_CHECK_PYMOD(numpy,,[HAVE_PYTHON_NUMPY=yes],[HAVE_PYTHON_NUMPY=no])
fi

AC_CHECK_PROG([HAVE_SWIG], [swig], ["yes"], ["no"])
if test "x$HAVE_SWIG" = "xyes" ; then
  case "$target_os" in
  darwin*)
        ;;
  *)
if test "x$HAVE_PYTHON_NUMPY" = "xyes"; then
   if test "x$with_pythonllib" = "xyes"; then
        DIRS="$DIRS ./pythonlib"
   fi
fi
if test "x$ac_cv_header_EXTERN_h" = "xyes"; then
   if test "x$with_perllib" = "xyes"; then
        DIRS="$DIRS ./perllib"
   fi
fi
        ;;
  esac
fi

AC_SUBST(PACKAGE_VERSION)
AC_SUBST(PACKAGE_RELEASE)
AC_SUBST(LIBS)
AC_SUBST(DIRS)
AC_SUBST(INCLS)
AC_SUBST(V_CCOPT)
AC_SUBST(V_INCLS)
AC_SUBST(V_INCLS_EXAMPLES)
AC_SUBST(V_PYTHON_INCLS)
AC_SUBST(V_RANLIB)
AC_SUBST(V_YACC)
AC_SUBST(V_LEX)
AC_SUBST(V_PERL)
AC_SUBST(V_THREADS)
AC_SUBST(V_FTDEP)
AC_SUBST(V_PCRE)
AC_SUBST(V_READLINE)
AC_SUBST(V_READLINE_INCLS)
AC_SUBST(V_GEOIPDEP)
AC_SUBST(WRAPLIBS)
AC_SUBST(COMPATLIB)
AC_SUBST(ZLIB)
AC_SUBST(DNSLIB)
AC_SUBST(CURSESLIB)
AC_SUBST(CURSES_INCLS)
AC_SUBST(LIB_XDR)
AC_SUBST(XDR_INCLS)
AC_SUBST(INSTALL_LIB)
AC_SUBST(INSTALL_BIN)
AC_SUBST(PCRE_CFLAGS)

AC_CONFIG_FILES([
   Makefile 
   ./common/Makefile 
   ./include/Makefile
   ./clients/Makefile 
   ./lib/argus-clients.pc
   ./pkg/rhel/systemd/rasqlinsert-setup
   ./pkg/Makefile
   ./lib/argus-clients.spec
])

AS_IF([test "$with_perllib" != no],
   [AC_CONFIG_FILES([
      ./perllib/Makefile
   ])]
)

AS_IF([test "$with_pythonlib" != no],
   [AC_CONFIG_FILES([
      ./pythonlib/Makefile
   ])]
)

AS_IF([test "$with_examples" != no],
   [AC_CONFIG_FILES([
      ./examples/Makefile
      ./examples/raconvert/Makefile
      ./examples/radbase/Makefile
      ./examples/radecode/Makefile
      ./examples/radns/Makefile
      ./examples/radump/Makefile
      ./examples/raevent/Makefile
      ./examples/rafilter/Makefile
      ./examples/ragraph/Makefile
      ./examples/ragrep/Makefile
      ./examples/rahisto/Makefile
      ./examples/ralabel/Makefile
   ])
   
   AS_IF([test "$ARGUS_MYSQL_MAKEFILE" != no],
      [AC_CONFIG_FILES([
         ./examples/ramysql/Makefile
         ./examples/rahosts/Makefile
      ])
   ])
   
   AC_CONFIG_FILES([
      ./examples/ramatrix/Makefile
      ./examples/rapath/Makefile
      ./examples/rapolicy/Makefile
      ./examples/raports/Makefile
      ./examples/raqsort/Makefile
      ./examples/rarpwatch/Makefile
      ./examples/raservices/Makefile
      ./examples/rastrip/Makefile
      ./examples/ratop/Makefile
      ./examples/ratrace/Makefile
      ./examples/ratimerange/Makefile
      ./examples/ratemplate/Makefile
   ])

   AS_IF([test x"$PERL" != x],
      AS_IF([test "$ARGUS_MYSQL_MAKEFILE" != no],
         [AC_CONFIG_FILES([
            ./examples/rahosts/raclique.pl
            ./examples/rahosts/rahostsdaily.pl
            ./examples/rahosts/rahostsv6.pl
         ])
      ])

      AC_CONFIG_FILES([
         ./examples/radark/radark.pl
         ./examples/radbase/raipdbase.pl
         ./examples/radecode/radecode.pl
         ./examples/radns/radnsdb.pl
         ./examples/ragraph/ragraph.pl
         ./examples/ragraph/raplot.pl
         ./examples/ramysql/radbaserollup.pl
         ./examples/ramysql/rastatus-cpustats.pl
         ./examples/ramysql/rastatus-dailylogs.pl
         ./examples/ramysql/rastatus-diskstats.pl
         ./examples/ramysql/rastatus-loadavg.pl
         ./examples/ramysql/rastatus-memstats.pl
         ./examples/raports/raportsdaily.pl
         ./examples/raports/raports.pl
      ])
   ])
)

AC_OUTPUT

if test -f .devel ; then
	make depend
fi
