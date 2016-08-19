dnl
dnl Copyright (C) 2000-2016 QoSient, LLC.
dnl
dnl Copyright (c) 1995, 1996, 1997, 1998
dnl   The Regents of the University of California.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that: (1) source code distributions
dnl retain the above copyright notice and this paragraph in its entirety, (2)
dnl distributions including binary code include the above copyright notice and
dnl this paragraph in its entirety in the documentation or other materials
dnl provided with the distribution, and (3) all advertising materials mentioning
dnl features or use of this software display the following acknowledgement:
dnl ``This product includes software developed by the University of California,
dnl Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
dnl the University nor the names of its contributors may be used to endorse
dnl or promote products derived from this software without specific prior
dnl written permission.
dnl THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
dnl WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl $Id: //depot/argus/clients/acsite.m4#45 $
dnl $DateTime: 2016/06/01 15:17:28 $
dnl $Change: 3148 $
dnl


dnl QOSIENT and LBL autoconf macros
dnl
dnl
dnl Check for flex require flex 2.4 or higher
dnl Check for bison define the yy prefix string
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_LEX_AND_YACC(lex, yacc, yyprefix)
dnl
dnl results:
dnl
dnl   $1 (lex set)
dnl   $2 (yacc appended)
dnl   $3 (optional flex and bison -P prefix)
dnl
AC_DEFUN([AC_QOSIENT_LEX_AND_YACC],
   [AC_CHECK_PROGS($1, flex, lex)
   if test "$$1" = flex ; then
      AC_MSG_CHECKING(for flex 2.4 or higher)
      AC_CACHE_VAL(ac_cv_lbl_flex_v24,
         if flex -V >/dev/null 2>&1; then
            ac_cv_lbl_flex_v24=yes
         else
            ac_cv_lbl_flex_v24=no
         fi)
      AC_MSG_RESULT($ac_cv_lbl_flex_v24)
      if test $ac_cv_lbl_flex_v24 = no ; then
         s="2.4 or higher required"
         AC_MSG_WARN(ignoring obsolete flex executable ($s))
         $1=lex
      fi
   else
      AC_MSG_ERROR(flex not found. see the INSTALL for more info)
   fi

   AC_CHECK_PROGS([$2], bison, yacc)

   if test "$$2" = bison ; then
      $2="$$2 -y"
   else
      AC_MSG_ERROR(bison not found. see the INSTALL for more info)
   fi

   if test "$$1" = flex -a -n "$3" ; then
      $1="$$1 -P$3"
      $2="$$2 -p $3"
   fi])

dnl
dnl Determine which compiler we're using (cc or gcc)
dnl If using gcc, determine the version number
dnl If using cc, require that it support ansi prototypes
dnl If using gcc, use -O3 (otherwise use -O)
dnl If using cc, explicitly specify /usr/local/include
dnl
dnl usage:
dnl
dnl   AC_LBL_C_INIT(copt, incls)
dnl
dnl results:
dnl
dnl   $1 (copt set)
dnl   $2 (incls set)
dnl   CC
dnl   LDFLAGS
dnl   ac_cv_lbl_gcc_vers
dnl   LBL_CFLAGS
dnl
m4_define([AC_LBL_C_INIT],
    [AC_PREREQ(2.12)
    AC_BEFORE([$0], [AC_PROG_CC])
    AC_BEFORE([$0], [AC_LBL_FIXINCLUDES])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_BEFORE([$0], [AC_QOSIENT_DEBUG])
    AC_ARG_WITH(gcc, [  --without-gcc           don't use gcc])
    AC_ARG_WITH(examples, [  --without-examples      don't compile examples])
    AC_ARG_WITH(pluribus,
            [AC_HELP_STRING([--with-pluribus],[Compile for pluribus])],
            with_pluribus="yes",
            with_pluribus="no")
    $1="-O"
    $2=""
    if test "${srcdir}" != "." ; then
       $2="-I\$(srcdir)"
    fi
    if test "${CFLAGS+set}" = set; then
       LBL_CFLAGS="$CFLAGS"
    fi
    if test -z "$CC" ; then
       case "$target_os" in

       *darwin*)
          AC_CHECK_PROG(CLANG, clang, yes, no)
          if test $CLANG = yes ; then
             CC=cc
             export CC
          fi
          ;;
       bsdi*)
          AC_CHECK_PROG(SHLICC2, shlicc2, yes, no)
          if test $SHLICC2 = yes ; then
             CC=shlicc2
             export CC
          fi
          ;;
       esac
    fi
    if test -z "$CC" -a "$with_gcc" = no ; then
       CC=cc
       export CC
    fi

    AC_PROG_CC

    if test "$GCC" = yes ; then
       if test "$SHLICC2" = yes ; then
          ac_cv_lbl_gcc_vers=2
          $1="-O3"
       else
          ac_cv_lbl_gcc_vers=0
          AC_MSG_CHECKING(gcc version)
          AC_CACHE_VAL(ac_cv_lbl_gcc_vers,
          ac_cv_lbl_gcc_vers=`$CC -v 2>&1 | \
             sed -e '/^gcc version /!d' \
            -e 's/^gcc version //' \
            -e 's/ .*//' -e 's/^[[[^0-9]]]*//' \
            -e 's/\..*//'`)
          AC_MSG_RESULT($ac_cv_lbl_gcc_vers)
          if test $ac_cv_lbl_gcc_vers -gt 1 ; then
             $1="-O3"
          fi
       fi
    else
       AC_MSG_CHECKING(that $CC handles ansi prototypes)
       AC_CACHE_VAL(ac_cv_lbl_cc_ansi_prototypes,
       AC_TRY_COMPILE(
          [#include <sys/types.h>],
          [int frob(int, char *)],
          ac_cv_lbl_cc_ansi_prototypes=yes,
          ac_cv_lbl_cc_ansi_prototypes=no))
       AC_MSG_RESULT($ac_cv_lbl_cc_ansi_prototypes)
       if test $ac_cv_lbl_cc_ansi_prototypes = no ; then
          case "$target_os" in

          hpux*)
             AC_MSG_CHECKING(for HP-UX ansi compiler ($CC -Aa -D_HPUX_SOURCE))
             savedcflags="$CFLAGS"
             CFLAGS="-Aa -D_HPUX_SOURCE $CFLAGS"
             AC_CACHE_VAL(ac_cv_lbl_cc_hpux_cc_aa,
            AC_TRY_COMPILE(
                [#include <sys/types.h>],
                [int frob(int, char *)],
                ac_cv_lbl_cc_hpux_cc_aa=yes,
                ac_cv_lbl_cc_hpux_cc_aa=no))
             AC_MSG_RESULT($ac_cv_lbl_cc_hpux_cc_aa)
             if test $ac_cv_lbl_cc_hpux_cc_aa = no ; then
                AC_MSG_ERROR(see the INSTALL doc for more info)
             fi
             CFLAGS="$savedcflags"
             V_CCOPT="-Aa $V_CCOPT"
             AC_DEFINE(_HPUX_SOURCE,1,[needed on HP-UX])
             ;;

          *)
             AC_MSG_ERROR(see the INSTALL doc for more info)
             ;;
          esac
       fi
       $2="$$2 -I/usr/local/include"
       LDFLAGS="$LDFLAGS -L/usr/local/lib"

       case "$target_os" in

       irix*)
          V_CCOPT="$V_CCOPT -xansi -signed -g3"
          ;;

       osf*)
          V_CCOPT="$V_CCOPT -std1 -g3"
          ;;

       ultrix*)
          AC_MSG_CHECKING(that Ultrix $CC hacks const in prototypes)
          AC_CACHE_VAL(ac_cv_lbl_cc_const_proto,
          AC_TRY_COMPILE(
             [#include <sys/types.h>],
             [struct a { int b; };
             void c(const struct a *)],
             ac_cv_lbl_cc_const_proto=yes,
             ac_cv_lbl_cc_const_proto=no))
          AC_MSG_RESULT($ac_cv_lbl_cc_const_proto)
          if test $ac_cv_lbl_cc_const_proto = no ; then
             AC_DEFINE([const],  [], [Description])
          fi
          ;;
       esac
    fi
])


dnl
dnl Check whether a given format can be used to print 64-bit integers
dnl
AC_DEFUN([AC_LBL_CHECK_64BIT_FORMAT],
  [
    AC_MSG_CHECKING([whether %$1x can be used to format 64-bit integers])
    AC_RUN_IFELSE(
      [
	AC_LANG_SOURCE(
	  [[
#	    ifdef HAVE_INTTYPES_H
	    #include <inttypes.h>
#	    endif
#	    ifdef HAVE_SYS_BITYPES_H
            #include <sys/bitypes.h>
#	    endif
	    #include <stdio.h>
	    #include <sys/types.h>

	    main()
	    {
	      u_int64_t t = 1;
	      char strbuf[16+1];
	      sprintf(strbuf, "%016$1x", t << 32);
	      if (strcmp(strbuf, "0000000100000000") == 0)
		exit(0);
	      else
		exit(1);
	    }
	  ]])
      ],
      [
	AC_DEFINE(PRId64, "$1d")
	AC_DEFINE(PRIo64, "$1o")
	AC_DEFINE(PRIx64, "$1x")
	AC_DEFINE(PRIu64, "$1u")
	AC_MSG_RESULT(yes)
      ],
      [
	AC_MSG_RESULT(no)
	$2
      ])
  ])


dnl
dnl Checks to see if unaligned memory accesses fail
dnl
dnl usage:
dnl
dnl   AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl   LBL_ALIGN (DEFINED)
dnl
AC_DEFUN([AC_LBL_UNALIGNED_ACCESS],
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
   [case "$target_cpu" in

   # XXX: should also check that they don't do weird things (like on arm)
   alpha*|arm*|hp*|mips|sparc)
      ac_cv_lbl_unaligned_fail=yes
      ;;

   *)
      cat >conftest.c <<EOF
#      include <sys/types.h>
#      include <sys/wait.h>
#      include <stdio.h>
      unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
      main() {
      unsigned int i;
      pid_t pid;
      int status;
      /* avoid "core dumped" message */
      pid = fork();
      if (pid <  0)
         exit(2);
      if (pid > 0) {
         /* parent */
         pid = waitpid(pid, &status, 0);
         if (pid < 0)
            exit(3);
         exit(!WIFEXITED(status));
      }
      /* child */
      i = *(unsigned int *)&a[[1]];
      printf("%d\n", i);
      exit(0);
      }
EOF
      ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
          conftest.c $LIBS >/dev/null 2>&1
      if test ! -x conftest ; then
         dnl failed to compile for some reason
         ac_cv_lbl_unaligned_fail=yes
      else
         ./conftest >conftest.out
         if test ! -s conftest.out ; then
            ac_cv_lbl_unaligned_fail=yes
         else
            ac_cv_lbl_unaligned_fail=no
         fi
      fi
      rm -rf conftest* core core.conftest
      ;;
   esac])
    AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
    if test $ac_cv_lbl_unaligned_fail = yes ; then
       AC_DEFINE([LBL_ALIGN], [], [Description])
    fi])


dnl
dnl If using gcc and the file .devel exists:
dnl   Compile with -g (if supported) and -Wall
dnl   If using gcc 2, do extra prototype checking
dnl   If an os prototype include exists, symlink os-proto.h to it
dnl
dnl usage:
dnl
dnl   AC_LBL_DEVEL(copt)
dnl
dnl results:
dnl
dnl   $1 (copt appended)
dnl

AC_DEFUN([AC_LBL_DEVEL],
    [rm -f os-proto.h
    if test "${LBL_CFLAGS+set}" = set; then
       $1="$$1 ${LBL_CFLAGS}"
    fi
    if test -f .devel ; then
       $1=`echo $$1 | sed -e 's/-O3//'`
       $1=`echo $$1 | sed -e 's/-O//'`
       if test "$GCC" = yes ; then
          if test "${LBL_CFLAGS+set}" != set; then
             if test "$ac_cv_prog_cc_g" = yes ; then
                $1="-g $$1"
             fi
             $1="$$1 -Wall -Wmissing-prototypes"
          fi
       else
          $1=`echo $$1 | sed -e 's/-O//'`
          case "$target_os" in
          solaris*)
             $1="$$1 -g"
             ;;

          irix6*)
             V_CCOPT="$V_CCOPT -n32"
             ;;

          *)
             ;;
          esac
       fi
    fi])

dnl
dnl If the file .debug exists:
dnl   Add ARGUS_DEBUG to the condefs.h file.
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_DEBUG(copt)
dnl
dnl results:
dnl
dnl   $1 (copt appended)
dnl


AC_DEFUN([AC_QOSIENT_DEBUG],
    [
    if test -f .debug ; then
       AC_DEFINE([ARGUSDEBUG], [], [Using Argus debug])
    fi])


dnl 
dnl If the file .threads exists:
dnl   Add ARGUS_THREADS to the condefs.h file.
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_THREADS(copt)
dnl
dnl results:
dnl
dnl   $1 (copt appended)
dnl
 
AC_DEFUN([AC_QOSIENT_THREADS],
  [AC_ARG_WITH(threads,
    [AC_HELP_STRING([--without-threads],[don't use native threads package])],
      with_threads="$withval",
      with_threads="yes")

  if test "$with_threads" != no; then
    case "$host_os" in
      *openbsd*)
        ;;

      *)
        AC_MSG_CHECKING(for .threads)
        if test -f .threads ; then
          AC_MSG_RESULT(yes)
          $1=""
          if test "$GCC" = yes ; then
            case "$host_os" in
              *darwin*)
                 ;;
              cygwin*)
                 ;;
              *)
                 $1="-lpthread $$1"
                 ;;
            esac
          else
            case "$host_os" in
                   solaris*)
                      $1="-mt -lpthread $$1"
                      ;;
                   cygwin*)
                      ;;
                   *darwin*)
                      ;;
                   *)
                      $1="-lpthread $$1"
                      ;;
            esac
          fi
          AC_DEFINE([ARGUS_THREADS], [], [Using Argus threads])
          AC_CHECK_FUNCS(sched_get_priority_min)
        else
          AC_MSG_RESULT(no)
        fi
        ;;
    esac
  fi
])


dnl
dnl Use pfopen.c if available and pfopen() not in standard libraries
dnl Require libft
dnl Look for libft in ..
dnl Use the installed libft if there is no local version
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_FLOWTOOLS(ftdep, incls)
dnl
dnl results:
dnl
dnl   $1 (ftdep set)
dnl   $2 (incls appended)
dnl   LIBS
dnl   LBL_LIBS
dnl

AC_DEFUN([AC_QOSIENT_FLOWTOOLS], [
   AC_ARG_WITH(libft,
            [AC_HELP_STRING([--with-libft=DIR],[Compile with libft in <DIR>])],
            with_libft="$withval",
            with_libft="yes")
   dnl
   dnl save a copy before locating libft.a
   dnl

   if test ${with_libft} != "no"; then
      if test "$ac_cv_header_zlib_h" = "yes"; then
         LBL_LIBS="$LIBS"
         libft=FAIL
         lastdir=FAIL

         if test ${with_libft} != "yes"; then
            AC_MSG_CHECKING(for specified library)
            for dir in ${with_libft}; do
               if test -r $dir/libft.a ; then
                  if test -x $dir/ft-config ; then
                     libft="$dir/libft.a `$dir/ft-config --additional-libs --static`"
                   else
                      libft=$dir/libft.a
                   fi
                   AC_MSG_RESULT($libft)
                   $1=$libft
                   AC_MSG_CHECKING(for specified ftlib.h)
                   if test -r $dir/ftlib.h; then
                      d=$dir
                      AC_MSG_RESULT(found)
                      $2="-I$d $$2"
                   else
                      AC_MSG_WARN(not found)
                   fi
               else
                 if test -r $dir/lib/libft.a ; then
                   if test -x $dir/lib/ft-config ; then
                     libft="$dir/lib/libft.a `$dir/lib/ft-config --additional-libs --static`"
                   else
                     libft=$dir/lib/libft.a
                   fi
                   AC_MSG_RESULT($libft)
                   $1=$libft
                   AC_MSG_CHECKING(for specified ftlib.h)
                   if test -r $dir/include/ftlib.h; then
                      d=$dir/include
                      AC_MSG_RESULT(found)
                      $2="-I$d $$2"
                   else
                      AC_MSG_WARN(not found)
                   fi
                 fi
               fi
            done
         else
            AC_MSG_CHECKING(for local ft library)
            places=`ls $srcdir/.. | sed -e 's,/$,,' -e "s,^,$srcdir/../," | \
               egrep '/flow-tools-[[0-9]]*.[[0-9]]*.[[0-9]]*'`
      
            for dir in $places/lib ; do
               if test -r $dir/libft.a ; then
                  if test -r $dir/ftlib.h ; then
                      d=`(cd $dir; pwd)`
                      libft=$d/libft.a
                  fi
                  dnl continue and select the last one that exists
               fi
            done
            if ! test "$libft" = FAIL; then
               AC_MSG_RESULT($libft)
               $1=$libft
               $2="-I$d $$2"
               AC_PATH_PROG(FT_CONFIG, ft-config,, $d)
               if test -n "$FT_CONFIG"; then
                  #
                  # The libft directory has a ft-config script.
                  # Use it to get any additioal libraries needed
                  # to link with the libft archive library in
                  # that directory
                  #
                  libft="$libft `$FT_CONFIG --additional-libs --static`"
               fi
            fi
         fi
      
         if test "$libft" = FAIL ; then
            AC_MSG_RESULT(not found)
            #
            # Look for ft-config.
            #
            AC_PATH_PROG(FT_CONFIG, ft-config)
            if test -n "$FT_CONFIG" ; then
               #
               # Found - use it to get the include flags for
               # libft and the flags to link with libft.
               #
               libft="`$FT_CONFIG --libs`"
      
               $2="`$FT_CONFIG --cflags` $$2"
               $1="$libft"
            else
               AC_CHECK_LIB(ft, main, libft="-lft")
               if ! test $libft = FAIL ; then
                  $1="$libft"
               fi
               AC_MSG_CHECKING(for extraneous ft header directories)
               if test -r /usr/include/ftlib.h; then
                  d="/usr/include"
                  AC_MSG_RESULT(found)
               else
                  $1=""
                  for dir in /usr/include /usr/local/include /usr/netflow/lib /usr/local/netflow/lib ; do 
                     if test -r $dir/ftlib.h; then
                         d=$dir
                         AC_MSG_RESULT(found)
                         $2="-I$d $$2"
                         $1="$libft"
                     fi
                  done
               fi
            fi
         fi
      else
         AC_MSG_CHECKING(flow-tools support)
         AC_MSG_RESULT(no requires zlib.h)
      fi
      LIBS="$LBL_LIBS"
   fi
])

dnl
dnl usage:
dnl
dnl   AC_QOSIENT_PCRE(pcrelib, incls)
dnl
dnl results:
dnl
dnl   $1 (pcrelib set)
dnl   $2 (incls appended)
dnl   LIBS
dnl   LBL_LIBS
dnl

AC_DEFUN([AC_QOSIENT_PCRE], [
   AC_ARG_WITH(libpcre,
            [AC_HELP_STRING([--with-libpcre=DIR],[Compile with libpcre in <DIR>])],
            with_libpcre="$withval",
            with_libpcre="no")

   if test ${with_libpcre} != "no"; then
      AC_MSG_CHECKING(for pcre library)
      AC_ARG_WITH(pcre-config, 
            [AC_HELP_STRING([--with-pcre-config=PATH], [Location of PCRE pcre-config (auto)])],
            with_pcre_config="$withval", 
            with_pcre_config="yes")

      if test ${with_pcre_config} != "no"; then
         if test -f $with_pcre_config ; then
            PCRE_CONFIG=$with_pcre_config
         else
            AC_CHECK_PROGS(PCRE_CONFIG, pcre-config)
         fi
      fi

      if test "x$PCRE_CONFIG" != "x"; then
         PCRE_CFLAGS=`$PCRE_CONFIG --cflags`
         PCRE_LIBS=`$PCRE_CONFIG --libs-posix`
      fi

      if test "x$PCRE_LIBS" != "x" ; then
         AC_DEFINE([ARGUS_PCRE], [], [Using System Pcre Library])
         $1=$PCRE_LIBS;
         $2="$PCRE_CFLAGS $$2"
      else
         AC_CHECK_HEADERS(regex.h,, AC_ERROR(neither pcre nor regex found))
      fi
   else
      AC_CHECK_HEADERS(regex.h,, AC_ERROR(regex not found))
   fi
])

dnl 
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_READLINE(lib, copt)
dnl
dnl results:
dnl
dnl   $1 (lib provided)
dnl   $2 (include provided)
dnl   $2 (copt appended)
dnl

AC_DEFUN([AC_QOSIENT_READLINE], [
   AC_ARG_WITH(readline,
            [AC_HELP_STRING([--with-readline=DIR],[Compile with readline in <DIR>])],
            with_readline="$withval",
            with_readline="yes")

   if test ${with_readline} != "no"; then
     saved_CPPFLAGS=$CPPFLAGS
     saved_LDFLAGS=$LDFLAGS
     saved_LIBS=$LIBS 

     if test ${with_readline} != "yes"; then
       CPPFLAGS="${saved_CPPFLAGS} -I${with_readline}/include"
       LDFLAGS="${save_LDFLAGS} -L${with_readline}/lib"
     else
        case "$target_os" in
        solaris*)
                dnl Workaround to look for readline on mac os x and solaris in /opt/local
                CPPFLAGS="${saved_CPPFLAGS} -I/opt/local/include"
                LDFLAGS="${save_LDFLAGS} -L/opt/local/lib"
                ;;
        darwin*)
                dnl Workaround to look for readline on mac os x and solaris in /opt/local
                CPPFLAGS="${saved_CPPFLAGS} -I/opt/local/include"
                LDFLAGS="${save_LDFLAGS} -L/opt/local/lib"
                ;;
        esac
     fi

     AC_CHECK_HEADERS(readline/readline.h,
       AC_CHECK_DECLS([rl_event_hook, rl_catch_signals, rl_done, rl_set_keyboard_input_timeout, rl_replace_line, rl_delete_text, rl_resize_terminal, rl_save_prompt  ], [] , [] ,
               [
                  #include <stdlib.h>
                  #include <stdio.h>
                  #include <readline/readline.h>
               ]), ac_cv_found_readline=no)
 
     if test "$ac_cv_found_readline" != no; then
       $1="-lreadline"
       $2="${CPPFLAGS} $$2"
       AC_DEFINE([ARGUS_READLINE], [], [Using System Readline Library])
     else
       LIBS=$saved_LIBS
       LDFLAGS=$saved_LDFLAGS
       CPPFLAGS=$saved_CPPFLAGS

       AC_CHECK_HEADER(editline/readline.h, [AC_CHECK_LIB(edit, el_init, ac_cv_found_el_init=yes, ac_cv_found_el_init=no)])

       if test "$ac_cv_found_el_init" = yes; then
            AC_DEFINE([ARGUS_EDITLINE], [], [Using System Editline Library])
            AC_CHECK_LIB(edit, history_init, ac_cv_found_history_init=yes, ac_cv_found_history_init=no)
            if test "$ac_cv_found_history_init" != no; then
               AC_DEFINE([ARGUS_HISTORY], [], [Using System history routines])
            fi
            $1="-ledit"
       fi
     fi
     echo "readline test finished cppflags ${CPPFLAGS} ldflags ${LDFLAGS} "
   fi
])


dnl
dnl If the file .memory exists:
dnl   Add ARGUSMEMDEBUG to the condefs.h file.
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_MEMORY(copt)
dnl
dnl results:
dnl
dnl   $1 (copt appended)
dnl


AC_DEFUN([AC_QOSIENT_MEMORY],
    [
    if test -f .memory ; then
       AC_DEFINE([ARGUSMEMDEBUG], [], [Using Argus memory])
    fi])


AC_DEFUN([AC_CMU_MYSQL],
   [AC_ARG_WITH(mysql,
      [  --with-mysql=DIR        use mysql in <DIR> [yes]],
      with_mysql="$withval")

MYSQL_INCLS=""
MYSQL_LDFLAGS=""
ARGUS_MYSQL=""
ARGUS_MYSQL_MAKEFILE=no

   if test "$with_mysql" != no; then
      saved_CPPFLAGS=$CPPFLAGS
      saved_LDFLAGS=$LDFLAGS
      saved_LIBS=$LIBS 

      case "$target_cpu" in
         x86_64)
            clib="lib64 lib"
            ;;
         *)
            clib="lib"
            ;;
      esac

      if test -n "$with_mysql"; then
         for dir in ${with_mysql}; do 
            for cdir in $clib; do 
               if test "$ac_cv_found_mysql" != yes; then 
                  unset ac_cv_header_mysql_h 
                  unset ac_cv_lib_mysqlclient_mysql_init 
                  unset ac_cv_lib_mysqlclient_r_mysql_init

                  if test -d $dir/$cdir/mysql; then
                     ac_cv_mysql_where_lib=$dir/$cdir/mysql
                  else
                     if test -d $dir/$cdir; then
                        ac_cv_mysql_where_lib=$dir/$cdir
                     fi
                  fi

                  if test -f $dir/include/mysql/mysql.h; then
                     ac_cv_mysql_where_inc=$dir/include/mysql
                  else 
                     if test -f $dir/include/mysql.h; then
                        ac_cv_mysql_where_inc=$dir/include
                     fi
                  fi

                  if test -f $ac_cv_mysql_where_inc/mysql.h; then
                     MYSQL_INCLS="-I$ac_cv_mysql_where_inc"
                     MYSQL_LDFLAGS="-L$ac_cv_mysql_where_lib"
                     CPPFLAGS="${saved_CPPFLAGS} ${MYSQL_INCLS}"
                     LDFLAGS="${saved_LDFLAGS} ${MYSQL_LDFLAGS}"

                     AC_CHECK_HEADER(mysql.h,
	             AC_CHECK_LIB(mysqlclient_r, mysql_init, ac_cv_found_mysql=yes, 
	             AC_CHECK_LIB(mysqlclient,   mysql_init, ac_cv_found_mysql=yes, ac_cv_found_mysql=no)),
		             ac_cv_found_mysql=no)

                     CPPFLAGS="${saved_CPPFLAGS}"
                     LDFLAGS="${saved_LDFLAGS}"
                  fi
               fi
            done
         done
      else
         for dir in /usr /usr/local /usr/local/mysql /usr/mysql; do 
            for cdir in $clib; do 
               if test "$ac_cv_found_mysql" != yes; then 
                  unset ac_cv_header_mysql_h 
                  unset ac_cv_lib_mysqlclient_mysql_init 
                  unset ac_cv_lib_mysqlclient_r_mysql_init

                  if test -d $dir/$cdir/mysql; then
                     ac_cv_mysql_where_lib=$dir/$cdir/mysql
                  else
                     if test -d $dir/$cdir; then
                        ac_cv_mysql_where_lib=$dir/$cdir
                     fi
                  fi

                  if test -f $dir/include/mysql/mysql.h; then
                     ac_cv_mysql_where_inc=$dir/include/mysql
                  else 
                     if test -f $dir/include/mysql.h; then
                        ac_cv_mysql_where_inc=$dir/include
                     fi
                  fi

                  if test -f $ac_cv_mysql_where_inc/mysql.h; then
                     MYSQL_INCLS="-I$ac_cv_mysql_where_inc"
                     MYSQL_LDFLAGS="-L$ac_cv_mysql_where_lib"
                     CPPFLAGS="${saved_CPPFLAGS} ${MYSQL_INCLS}"
                     LDFLAGS="${saved_LDFLAGS} ${MYSQL_LDFLAGS}"

                     AC_CHECK_HEADER(mysql.h,
	             AC_CHECK_LIB(mysqlclient_r, mysql_init, ac_cv_found_mysql=yes, 
	             AC_CHECK_LIB(mysqlclient,   mysql_init, ac_cv_found_mysql=yes, ac_cv_found_mysql=no)),
		             ac_cv_found_mysql=no)

                     CPPFLAGS="${saved_CPPFLAGS}"
                     LDFLAGS="${saved_LDFLAGS}"
                  fi
               fi
            done
         done
      fi

      if test "$ac_cv_found_mysql" = yes; then
         LIBS="$saved_LIBS"
         LDFLAGS="$saved_LDFLAGS"
         CPPFLAGS="$saved_CPPFLAGS"

         if test "$ac_cv_lib_mysqlclient_r_mysql_init" = yes; then
            MYSQL_LDFLAGS="$MYSQL_LDFLAGS -lmysqlclient_r"
         else
            if test "$ac_cv_lib_mysqlclient_mysql_init" = yes; then
               MYSQL_LDFLAGS="$MYSQL_LDFLAGS -lmysqlclient"
            fi
         fi

         ARGUS_MYSQL="./ramysql"
         ARGUS_MYSQL_MAKEFILE="./examples/ramysql/Makefile"
         AC_SUBST(MYSQL_LDFLAGS)
         AC_SUBST(MYSQL_INCLS)
         AC_SUBST(ARGUS_MYSQL)
         AC_DEFINE([ARGUS_MYSQL], [], [Description])
      else
         echo checking for mysql... no
      fi
   fi
   ])# AC_CMU_MYSQL

dnl
dnl Find libwrappers
dnl Look for libwrappers in ..
dnl Use the installed libwrappers if there is no local version
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_TCPWRAP(wrapdep, incls)
dnl
dnl results:
dnl
dnl   $1 (wrapdep set)
dnl   $2 (incls appended)
dnl   LIBS
dnl   LBL_LIBS
dnl
AC_DEFUN([AC_QOSIENT_TCPWRAP],
   [AC_MSG_CHECKING(for local tcp_wrappers library)
   libwrap=FAIL
   lastdir=FAIL
   pwdir=`pwd`
   places=`ls .. | sed -e 's,/$,,' -e 's,^,../,' | egrep 'tcp_wrappers'`
   for dir in $places; do
      if test $lastdir = $dir ; then
         dnl skip alphas when an actual release is present
         continue;
      fi
      lastdir=$dir
      if test -r $dir/libwrap.a ; then
         libwrap=$dir/libwrap.a
         d=$dir
         dnl continue and select the last one that exists
      fi
   done

   if test $libwrap = FAIL ; then
      AC_MSG_RESULT(not found)
      AC_MSG_CHECKING(for system tcp_wrappers library)
      AC_CACHE_VAL(ac_cv_qosient_wrapper,
        [ac_save_LIBS="$LIBS"
         LIBS="-lwrap"
         INCS=$$2
         $2=" "
         AC_TRY_COMPILE(
            [#include <tcpd.h>
             int deny_severity = 0, allow_severity = 0;],
            [struct request_info request;
             fromhost(&request);],
            ac_cv_qosient_wrapper=yes,
            ac_cv_qosient_wrapper=no)
         LIBS="$ac_save_LIBS"
         $2=$INCS])
      AC_MSG_RESULT($ac_cv_qosient_wrapper)
      if ! test $ac_cv_qosient_wrapper = no ; then
         libwrap="-lwrap"
      fi
   fi

   if ! test $libwrap = FAIL ; then
      $1=$libwrap
      if test -r $d/tcpd.h; then
         $2="-I$d $$2"
      elif test -r $srcdir/../libwrap/tcpd.h; then
         $2="-I$srcdir/../libwrap $$2"
      elif test -r /usr/local/include/tcpd.h; then
         $2="-I/usr/local/include $$2"
      elif test -r /opt/local/include/tcpd.h; then
         $2="-I/opt/local/include $$2"
         $1="-L/opt/local/lib $$1"
      elif test -r /usr/include/tcpd.h; then
         $2="-I$d -I$srcdir/../libwrap $$2"
      else
         AC_MSG_WARN(cannot find tcpd.h)
         libwrap=FAIL
      fi
   fi])

dnl
dnl Improved version of AC_CHECK_LIB
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl   AC_LBL_CHECK_LIB(LIBRARY, FUNCTION [, ACTION-IF-FOUND [,
dnl       ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl
dnl results:
dnl
dnl   LIBS
dnl

AC_DEFUN([AC_LBL_CHECK_LIB],
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $1 defining function $2, not
dnl just for library $1.  Separate tests with the same $1 and different $2's
dnl may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
       [$2()],
       eval "ac_cv_lbl_lib_$ac_lib_var=yes",
       eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])


dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.

dnl It has been argued that this test should be broken up into two
dnl seperate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independantly potentially results in unfortunate ordering
dnl dependancies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN([AC_LBL_LIBRARY_NET], [
    # Most operating systems have gethostbyname() in the default searched
    # libraries (i.e. libc):
    # Some OSes (eg. Solaris) place it in libnsl
    # Some strange OSes (SINIX) have it in libsocket:
    AC_SEARCH_LIBS(gethostbyname, nsl socket resolv)
    # Unfortunately libsocket sometimes depends on libnsl and
    # AC_SEARCH_LIBS isn't up to the task of handling dependencies like this.
    if test "$ac_cv_search_gethostbyname" = "no"
    then
   AC_CHECK_LIB(socket, gethostbyname,
                     LIBS="-lsocket -lnsl $LIBS", , -lnsl)
    fi
    AC_SEARCH_LIBS(socket, socket, ,
   AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", , -lnsl))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_SEARCH_LIBS(putmsg, str)
    ])


dnl
dnl If using gcc, make sure we have ANSI ioctl definitions
dnl
dnl usage:
dnl
dnl     AC_LBL_FIXINCLUDES
dnl
AC_DEFUN([AC_LBL_FIXINCLUDES],
    [if test "$GCC" = yes ; then
            AC_MSG_CHECKING(for ANSI ioctl definitions)
            AC_CACHE_VAL(ac_cv_lbl_gcc_fixincludes,
                AC_TRY_COMPILE(
                    [/*
                     * This generates a "duplicate case value" when fixincludes
                     * has not be run.
                     */
#               include <sys/types.h>
#               include <sys/time.h>
#               include <sys/ioctl.h>
#               ifdef HAVE_SYS_IOCCOM_H
#               include <sys/ioccom.h>
#               endif],
                    [switch (0) {
                    case _IO('A', 1):;
                    case _IO('B', 1):;
                    }],
                    ac_cv_lbl_gcc_fixincludes=yes,
                    ac_cv_lbl_gcc_fixincludes=no))
            AC_MSG_RESULT($ac_cv_lbl_gcc_fixincludes)
            if test $ac_cv_lbl_gcc_fixincludes = no ; then
                    # Don't cache failure
                    unset ac_cv_lbl_gcc_fixincludes
                    AC_MSG_ERROR(see the INSTALL for more info)
            fi
    fi])


AC_DEFUN([CMU_TEST_LIBPATH], [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_lib, <<- *>>, <<__p>>))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -r "$1/lib$2.a" -a \! -r "$1/lib$2.so" -a \! -r "$1/lib$2.sl" -a \! -r "$1/lib$2.dylib"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

AC_DEFUN([CMU_TEST_INCPATH], [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_inc, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -r "$1/$2.h"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

dnl CMU_CHECK_HEADER_NOCACHE(HEADER-FILE, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
AC_DEFUN([CMU_CHECK_HEADER_NOCACHE],
[dnl Do the transliteration at runtime so arg 1 can be a shell variable.
ac_safe=`echo "$1" | sed 'y%./+-%__p_%'`
AC_MSG_CHECKING([for $1])
AC_TRY_CPP([#include <$1>], eval "ac_cv_header_$ac_safe=yes",
  eval "ac_cv_header_$ac_safe=no")
if eval "test \"`echo '$ac_cv_header_'$ac_safe`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$2], , :, [$2])
else
  AC_MSG_RESULT(no)
ifelse([$3], , , [$3
])dnl
fi
])

AC_DEFUN([CMU_FIND_LIB_SUBDIR],
[dnl
AC_ARG_WITH([lib-subdir], AC_HELP_STRING([--with-lib-subdir=DIR],[Find libraries in DIR instead of lib]))
AC_CHECK_SIZEOF(long)
AC_CACHE_CHECK([what directory libraries are found in], [ac_cv_cmu_lib_subdir],
[test "X$with_lib_subdir" = "Xyes" && with_lib_subdir=
test "X$with_lib_subdir" = "Xno" && with_lib_subdir=
if test "X$with_lib_subdir" = "X" ; then
  ac_cv_cmu_lib_subdir=lib
  if test $ac_cv_sizeof_long -eq 4 ; then
    test -d /usr/lib32 && ac_cv_cmu_lib_subdir=lib32
  fi
  if test $ac_cv_sizeof_long -eq 8 ; then
    test -d /usr/lib64 && ac_cv_cmu_lib_subdir=lib64
  fi
else
  ac_cv_cmu_lib_subdir=$with_lib_subdir
fi])
AC_SUBST(CMU_LIB_SUBDIR, $ac_cv_cmu_lib_subdir)
])


dnl sasl.m4--sasl libraries and includes
dnl Derrick Brashear
dnl from KTH sasl and Arla
dnl $Id: //depot/argus/clients/acsite.m4#45 $

AC_DEFUN([CMU_SASL_INC_WHERE1], [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
CMU_CHECK_HEADER_NOCACHE(sasl.h,
ac_cv_found_sasl_inc=yes,
ac_cv_found_sasl_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN([CMU_SASL_INC_WHERE], [
   for i in $1; do
      CMU_SASL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, sasl)
      if test "$ac_cv_found_sasl_inc" = "yes"; then
        ac_cv_sasl_where_inc=$i
        break
      fi
    done
])

AC_DEFUN([CMU_SASL_LIB_WHERE1], [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lsasl"
AC_TRY_LINK(,
[sasl_getprop();],
[ac_cv_found_sasl_lib=yes],
ac_cv_found_sasl_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN([CMU_SASL_LIB_WHERE], [
   for i in $1; do
      CMU_SASL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, sasl)
      if test "$ac_cv_found_sasl_lib" = "yes" ; then
        ac_cv_sasl_where_lib=$i
        break
      fi
    done
])

AC_DEFUN([CMU_SASL], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(sasl,
            [  --with-sasl=DIR|no  use with libsasl in <DIR> no],
	    with_sasl="$withval",
            with_sasl="no")

if test ${with_sasl} != "no"; then
	SASLFLAGS=""
	LIB_SASL=""

	cmu_saved_CPPFLAGS=$CPPFLAGS
	cmu_saved_LDFLAGS=$LDFLAGS
	cmu_saved_LIBS=$LIBS
	if test -d ${with_sasl}; then
          ac_cv_sasl_where_lib=${with_sasl}/$CMU_LIB_SUBDIR
          ac_cv_sasl_where_inc=${with_sasl}/include

	  SASLFLAGS="-I$ac_cv_sasl_where_inc"
	  LIB_SASL="-L$ac_cv_sasl_where_lib"
	  CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
	  LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
	fi

	AC_CHECK_HEADER(sasl.h,
	  AC_CHECK_LIB(sasl, sasl_getprop, 
                       ac_cv_found_sasl=yes,
		       ac_cv_found_sasl=no), ac_cv_found_sasl=no)

	LIBS="$cmu_saved_LIBS"
	LDFLAGS="$cmu_saved_LDFLAGS"
	CPPFLAGS="$cmu_saved_CPPFLAGS"
	if test "$ac_cv_found_sasl" = yes; then
	  LIB_SASL="$LIB_SASL -lsasl"
	else
          AC_ERROR( sasl not found )
	  LIB_SASL=""
	  SASLFLAGS=""
	fi
	AC_SUBST(LIB_SASL)
	AC_SUBST(SASLFLAGS)
fi
])

AC_DEFUN([CMU_SASL_REQUIRED],
[AC_REQUIRE([CMU_SASL])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without libsasl.
Get it from ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/.])
fi])


# sasl2.m4--sasl2 libraries and includes
# Rob Siemborski
# $Id: //depot/argus/clients/acsite.m4#45 $

# SASL2_CRYPT_CHK
# ---------------
AC_DEFUN([SASL_GSSAPI_CHK],
[AC_REQUIRE([SASL2_CRYPT_CHK])
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_ENABLE([gssapi],
              [AC_HELP_STRING([--enable-gssapi=<DIR>],
                              [enable GSSAPI authentication [yes]])],
              [gssapi=$enableval],
              [gssapi=yes])
AC_ARG_WITH([gss_impl],
            [AC_HELP_STRING([--with-gss_impl={heimdal|mit|cybersafe|seam|auto}],
                            [choose specific GSSAPI implementation [[auto]]])],
            [gss_impl=$withval],
            [gss_impl=auto])

if test "$gssapi" != no; then
  platform=
  case "${host}" in
    *-*-linux*)
      platform=__linux
      ;;
    *-*-hpux*)
      platform=__hpux
      ;;
    *-*-irix*)
      platform=__irix
      ;;
    *-*-solaris2*)
# When should we use __sunos?
      platform=__solaris
      ;;
    *-*-aix*)
###_AIX
      platform=__aix
      ;;
    *)
      if test "$gss_impl" = "cybersafe"; then
        AC_ERROR([CyberSafe was forced, cannot continue as platform is not supported])
      fi
      ;;
  esac

  cmu_saved_CPPFLAGS=$CPPFLAGS

  if test -d ${gssapi}; then
    CPPFLAGS="$CPPFLAGS -I$gssapi/include"
# We want to keep -I in our CPPFLAGS, but only if we succeed
    cmu_saved_CPPFLAGS=$CPPFLAGS
### I am not sure how useful is this (and whether this is required at all
### especially when we have to provide two -L flags for new CyberSafe
    LDFLAGS="$LDFLAGS -L$gssapi/lib"

    if test -n "$platform"; then
      if test "$gss_impl" = "auto" -o "$gss_impl" = "cybersafe"; then
        CPPFLAGS="$CPPFLAGS -D$platform"
        if test -d "${gssapi}/appsec-sdk/include"; then
          CPPFLAGS="$CPPFLAGS -I${gssapi}/appsec-sdk/include"
        fi
      fi
    fi
  fi
  AC_CHECK_HEADER([gssapi.h],
                  [AC_DEFINE(HAVE_GSSAPI_H,,
                             [Define if you have the gssapi.h header file])],
                  [AC_CHECK_HEADER([gssapi/gssapi.h],,
                                   [AC_WARN([Disabling GSSAPI - no include files found]); gssapi=no])])

  CPPFLAGS=$cmu_saved_CPPFLAGS

fi

if test "$gssapi" != no; then
  # We need to find out which gssapi implementation we are
  # using. Supported alternatives are: MIT Kerberos 5,
  # Heimdal Kerberos 5 (http://www.pdc.kth.se/heimdal),
  # CyberSafe Kerberos 5 (http://www.cybersafe.com/)
  # and Sun SEAM (http://wwws.sun.com/software/security/kerberos/)
  #
  # The choice is reflected in GSSAPIBASE_LIBS

  AC_CHECK_LIB(resolv,res_search)
  if test -d ${gssapi}; then
     gssapi_dir="${gssapi}/lib"
     GSSAPIBASE_LIBS="-L$gssapi_dir"
     GSSAPIBASE_STATIC_LIBS="-L$gssapi_dir"
  else
     # FIXME: This is only used for building cyrus, and then only as
     # a real hack.  it needs to be fixed.
     gssapi_dir="/usr/local/lib"
  fi

  # Check a full link against the Heimdal libraries.
  # If this fails, check a full link against the MIT libraries.
  # If this fails, check a full link against the CyberSafe libraries.
  # If this fails, check a full link against the Solaris 8 and up libgss.

  if test "$gss_impl" = "auto" -o "$gss_impl" = "heimdal"; then
    gss_failed=0
    AC_CHECK_LIB(gssapi,gss_unwrap,gss_impl="heimdal",gss_failed=1,
                 ${GSSAPIBASE_LIBS} -lgssapi -lkrb5 -lasn1 -lroken ${LIB_CRYPT} ${LIB_DES} -lcom_err ${LIB_SOCKET})
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  if test "$gss_impl" = "auto" -o "$gss_impl" = "mit"; then
    # check for libkrb5support first
    AC_CHECK_LIB(krb5support,krb5int_getspecific,K5SUP=-lkrb5support K5SUPSTATIC=$gssapi_dir/libkrb5support.a,,${LIB_SOCKET})

    gss_failed=0
    AC_CHECK_LIB(gssapi_krb5,gss_unwrap,gss_impl="mit",gss_failed=1,
                 ${GSSAPIBASE_LIBS} -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${K5SUP} ${LIB_SOCKET})
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  # For Cybersafe one has to set a platform define in order to make compilation work
  if test "$gss_impl" = "auto" -o "$gss_impl" = "cybersafe"; then

    cmu_saved_CPPFLAGS=$CPPFLAGS
    cmu_saved_GSSAPIBASE_LIBS=$GSSAPIBASE_LIBS
# FIXME - Note that the libraries are in .../lib64 for 64bit kernels
    if test -d "${gssapi}/appsec-rt/lib"; then
      GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -L${gssapi}/appsec-rt/lib"
    fi
    CPPFLAGS="$CPPFLAGS -D$platform"
    if test -d "${gssapi}/appsec-sdk/include"; then
      CPPFLAGS="$CPPFLAGS -I${gssapi}/appsec-sdk/include"
    fi

    gss_failed=0

# Check for CyberSafe with two libraries first, than fall back to a single 
# library (older CyberSafe)

    unset ac_cv_lib_gss_csf_gss_acq_user
    AC_CHECK_LIB(gss,csf_gss_acq_user,gss_impl="cybersafe03",
                 [unset ac_cv_lib_gss_csf_gss_acq_user;
                  AC_CHECK_LIB(gss,csf_gss_acq_user,gss_impl="cybersafe",
                               gss_failed=1,$GSSAPIBASE_LIBS -lgss)],
                 [${GSSAPIBASE_LIBS} -lgss -lcstbk5])

    if test "$gss_failed" = "1"; then
# Restore variables
      GSSAPIBASE_LIBS=$cmu_saved_GSSAPIBASE_LIBS
      CPPFLAGS=$cmu_saved_CPPFLAGS

      if test "$gss_impl" != "auto"; then
        gss_impl="failed"
      fi
    fi
  fi

  if test "$gss_impl" = "auto" -o "$gss_impl" = "seam"; then
    gss_failed=0
    AC_CHECK_LIB(gss,gss_unwrap,gss_impl="seam",gss_failed=1,-lgss)
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  if test "$gss_impl" = "mit"; then
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${K5SUP}"
    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_LIBS $gssapi_dir/libgssapi_krb5.a $gssapi_dir/libkrb5.a $gssapi_dir/libk5crypto.a $gssapi_dir/libcom_err.a ${K5SUPSTATIC}"
  elif test "$gss_impl" = "heimdal"; then
    CPPFLAGS="$CPPFLAGS -DKRB5_HEIMDAL"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi -lkrb5 -lasn1 -lroken ${LIB_CRYPT} ${LIB_DES} -lcom_err"
    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_STATIC_LIBS $gssapi_dir/libgssapi.a $gssapi_dir/libkrb5.a $gssapi_dir/libasn1.a $gssapi_dir/libroken.a $gssapi_dir/libcom_err.a ${LIB_CRYPT}"
  elif test "$gss_impl" = "cybersafe03"; then
# Version of CyberSafe with two libraries
    CPPFLAGS="$CPPFLAGS -D$platform -I${gssapi}/appsec-sdk/include"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgss -lcstbk5"
    # there is no static libgss for CyberSafe
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "cybersafe"; then
    CPPFLAGS="$CPPFLAGS -D$platform -I${gssapi}/appsec-sdk/include"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgss"
    # there is no static libgss for CyberSafe
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "seam"; then
    GSSAPIBASE_LIBS=-lgss
    # there is no static libgss on Solaris 8 and up
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "failed"; then
    gssapi="no"
    GSSAPIBASE_LIBS=
    GSSAPIBASE_STATIC_LIBS=
    AC_WARN([Disabling GSSAPI - specified library not found])
  else
    gssapi="no"
    GSSAPIBASE_LIBS=
    GSSAPIBASE_STATIC_LIBS=
    AC_WARN([Disabling GSSAPI - no library])
  fi
fi

#
# Cybersafe defines both GSS_C_NT_HOSTBASED_SERVICE and GSS_C_NT_USER_NAME
# in gssapi\rfckrb5.h
#
if test "$gssapi" != "no"; then
  if test "$gss_impl" = "cybersafe" -o "$gss_impl" = "cybersafe03"; then
    AC_EGREP_CPP(hostbased_service_gss_nt_yes,
                 [#include <gssapi/gssapi.h>
                  #ifdef GSS_C_NT_HOSTBASED_SERVICE
                    hostbased_service_gss_nt_yes
                  #endif],
                 [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                            [Define if your GSSAPI implimentation defines GSS_C_NT_HOSTBASED_SERVICE])],
                 [AC_WARN([Cybersafe define not found])])

  elif test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                               [Define if your GSSAPI implimentation defines GSS_C_NT_HOSTBASED_SERVICE])])
  elif test "$ac_cv_header_gssapi_gssapi_h"; then
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi/gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                               [Define if your GSSAPI implimentation defines GSS_C_NT_HOSTBASED_SERVICE])])
  fi

  if test "$gss_impl" = "cybersafe" -o "$gss_impl" = "cybersafe03"; then
    AC_EGREP_CPP(user_name_yes_gss_nt,
                 [#include <gssapi/gssapi.h>
                  #ifdef GSS_C_NT_USER_NAME
                   user_name_yes_gss_nt
                  #endif],
                 [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                            [Define if your GSSAPI implimentation defines GSS_C_NT_USER_NAME])],
                 [AC_WARN([Cybersafe define not found])])
  elif test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_NT_USER_NAME, gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                               [Define if your GSSAPI implimentation defines GSS_C_NT_USER_NAME])])
  elif test "$ac_cv_header_gssapi_gssapi_h"; then
    AC_EGREP_HEADER(GSS_C_NT_USER_NAME, gssapi/gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                               [Define if your GSSAPI implimentation defines GSS_C_NT_USER_NAME])])
  fi
fi

GSSAPI_LIBS=""
AC_MSG_CHECKING([GSSAPI])
if test "$gssapi" != no; then
  AC_MSG_RESULT([with implementation ${gss_impl}])
  AC_CHECK_LIB(resolv,res_search,GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lresolv")
  SASL_MECHS="$SASL_MECHS libgssapiv2.la"
  SASL_STATIC_OBJS="$SASL_STATIC_OBJS gssapi.o"
  SASL_STATIC_SRCS="$SASL_STATIC_SRCS ../plugins/gssapi.c"

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  AC_CHECK_FUNCS(gsskrb5_register_acceptor_identity)
  LIBS="$cmu_save_LIBS"
else
  AC_MSG_RESULT([disabled])
fi
AC_SUBST(GSSAPI_LIBS)
AC_SUBST(GSSAPIBASE_LIBS)
])# SASL_GSSAPI_CHK


# SASL_SET_GSSAPI_LIBS
# --------------------
AC_DEFUN([SASL_SET_GSSAPI_LIBS],
[SASL_GSSAPI_LIBS_SET="yes"
])


# CMU_SASL2
# ---------
# What we want to do here is setup LIB_SASL with what one would
# generally want to have (e.g. if static is requested, make it that,
# otherwise make it dynamic.
#
# We also want to create LIB_DYN_SASL and DYNSASLFLAGS.
#
# Also sets using_static_sasl to "no" "static" or "staticonly"
#	
#	$1 (incls appended)
#
#
AC_DEFUN([CMU_SASL2],
[
   AC_ARG_WITH(sasl,
            [AC_HELP_STRING([--with-sasl=DIR],[Compile with libsasl2 in <DIR>])],
            with_sasl="$withval",
            with_sasl="no")

   AC_ARG_WITH(staticsasl,
            [AC_HELP_STRING([--with-staticsasl=DIR],
                            [Compile with staticly linked libsasl in <DIR>])],
            [with_staticsasl="$withval";
             if test $with_staticsasl != "no"; then
               using_static_sasl="static"
             fi],
            [with_staticsasl="no"; using_static_sasl="no"])

   if test ${with_staticsasl} != "no" || 
      test ${with_sasl}       != "no"; then 

   SASLFLAGS=""
   LIB_SASL=""

   cmu_saved_CPPFLAGS=$CPPFLAGS
   cmu_saved_LDFLAGS=$LDFLAGS
   cmu_saved_LIBS=$LIBS

   if test ${with_staticsasl} != "no"; then
      if test -d ${with_staticsasl}; then
         if test -d ${with_staticsasl}/lib64 ; then
            ac_cv_sasl_where_lib=${with_staticsasl}/lib64
         else
            ac_cv_sasl_where_lib=${with_staticsasl}/lib
         fi
         ac_cv_sasl_where_lib=${with_staticsasl}/lib
         ac_cv_sasl_where_inc=${with_staticsasl}/include

         SASLFLAGS="-I$ac_cv_sasl_where_inc"
         LIB_SASL="-L$ac_cv_sasl_where_lib"
         CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
         LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
      else
         with_staticsasl="/usr"
      fi

      AC_CHECK_HEADER(sasl/sasl.h,
         [AC_CHECK_HEADER(sasl/saslutil.h,
            [for i42 in lib64 lib; do
               if test -r ${with_staticsasl}/$i42/libsasl2.a; then
                  ac_cv_found_sasl=yes
                  AC_MSG_CHECKING([for static libsasl])
                  LIB_SASL="$LIB_SASL ${with_staticsasl}/$i42/libsasl2.a"
               fi
            done
         if test ! "$ac_cv_found_sasl" = "yes"; then
            AC_MSG_CHECKING([for static libsasl])
            AC_ERROR([Could not find ${with_staticsasl}/lib*/libsasl2.a])
         fi])])

      if test "$ac_cv_found_sasl" = "yes"; then
         AC_MSG_RESULT([found])
      else
         AC_ERROR([Could not find ${with_staticsasl}/lib*/libsasl2.a])
      fi
   fi

   if test -d ${with_sasl}; then
      ac_cv_sasl_where_lib=${with_sasl}/lib
      ac_cv_sasl_where_inc=${with_sasl}/include

      DYNSASLFLAGS="-I$ac_cv_sasl_where_inc"
      CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
      LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
      LIBS="-L$ac_cv_sasl_where_lib"
   fi

# be sure to check for a SASLv2 specific function
   AC_CHECK_HEADER(sasl/sasl.h,
      [AC_CHECK_HEADER(sasl/saslutil.h,
         [AC_CHECK_LIB(sasl2, prop_get, 
            ac_cv_found_sasl=yes,
            ac_cv_found_sasl=no)],
            ac_cv_found_sasl=no)], ac_cv_found_sasl=no)

   if test ${with_sasl} != "no"; then
      if test "$ac_cv_found_sasl" = "yes"; then
         if test "$ac_cv_sasl_where_lib" != ""; then
            DYNLIB_SASL="-L$ac_cv_sasl_where_lib"
         fi
         DYNLIB_SASL="$DYNLIB_SASL -lsasl2"
         if test "$using_static_sasl" != "static"; then
            LIB_SASL=$DYNLIB_SASL
            SASLFLAGS=$DYNSASLFLAGS
         fi

         CMU_SASL2_REQUIRE_VER(2,1,7)

         if test "$ac_cv_sasl_where_inc" != ""; then
            $1="-I$ac_cv_sasl_where_inc $$1"
         fi
         AC_DEFINE([ARGUS_SASL], [], [Description])
         AC_SUBST(LIB_SASL)
         AC_SUBST(SASLFLAGS)
      else
         AC_ERROR([Could not find sasl2])
      fi
   fi

   LIBS="$cmu_saved_LIBS"
   LDFLAGS="$cmu_saved_LDFLAGS"
   CPPFLAGS="$cmu_saved_CPPFLAGS"
   fi
])# CMU_SASL2


# CMU_SASL2_REQUIRE_VER
# ---------------------
AC_DEFUN([CMU_SASL2_REQUIRE_VER],
[

cmu_saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS $SASLFLAGS"

AC_TRY_CPP([
#include <sasl/sasl.h>

#ifndef SASL_VERSION_MAJOR
#error SASL_VERSION_MAJOR not defined
#endif
#ifndef SASL_VERSION_MINOR
#error SASL_VERSION_MINOR not defined
#endif
#ifndef SASL_VERSION_STEP
#error SASL_VERSION_STEP not defined
#endif

#if SASL_VERSION_MAJOR < $1 || SASL_VERSION_MINOR < $2 || SASL_VERSION_STEP < $3
#error SASL version is less than $1.$2.$3
#endif
],,
           [AC_ERROR([Incorrect SASL headers found.  This package requires SASL $1.$2.$3 or newer.])])

CPPFLAGS=$cmu_saved_CPPFLAGS
])# CMU_SASL2_REQUIRE_VER


dnl
dnl Additional macros for configure.in packaged up for easier theft.
dnl $Id: //depot/argus/clients/acsite.m4#45 $
dnl tjs@andrew.cmu.edu 6-may-1998
dnl

dnl It would be good if ANDREW_ADD_LIBPATH could detect if something was
dnl already there and not redundantly add it if it is.

dnl add -L(arg), and possibly (runpath switch)(arg), to LDFLAGS
dnl (so the runpath for shared libraries is set).
AC_DEFUN([CMU_ADD_LIBPATH], [
  # this is CMU ADD LIBPATH
  if test "$andrew_runpath_switch" = "none" ; then
        LDFLAGS="-L$1 ${LDFLAGS}"
  else
        LDFLAGS="-L$1 $andrew_runpath_switch$1 ${LDFLAGS}"
  fi
])

dnl add -L(1st arg), and possibly (runpath switch)(1st arg), to (2nd arg)
dnl (so the runpath for shared libraries is set).
AC_DEFUN([CMU_ADD_LIBPATH_TO], [
  # this is CMU ADD LIBPATH TO
  if test "$andrew_runpath_switch" = "none" ; then
        $2="-L$1 ${$2}"
  else
        $2="-L$1 ${$2} $andrew_runpath_switch$1"
  fi
])

dnl runpath initialization
AC_DEFUN([CMU_GUESS_RUNPATH_SWITCH], [
   # CMU GUESS RUNPATH SWITCH
  AC_CACHE_CHECK(for runpath switch, andrew_runpath_switch, [
    # first, try -R
    SAVE_LDFLAGS="${LDFLAGS}"
    LDFLAGS="-R /usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-R"], [
        LDFLAGS="-Wl,-rpath,/usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-Wl,-rpath,"],
    [andrew_runpath_switch="none"])
    ])
  LDFLAGS="${SAVE_LDFLAGS}"
  ])])

AC_DEFUN([SASL2_CRYPT_CHK],[
 AC_CHECK_FUNC(crypt, cmu_have_crypt=yes, [
  AC_CHECK_LIB(crypt, crypt,
               LIB_CRYPT="-lcrypt"; cmu_have_crypt=yes,
               cmu_have_crypt=no)])
 AC_SUBST(LIB_CRYPT)
])

dnl bsd_sockets.m4--which socket libraries do we need?
dnl Derrick Brashear
dnl from Zephyr
dnl $Id: //depot/argus/clients/acsite.m4#45 $

dnl Hacked on by Rob Earhart to not just toss stuff in LIBS
dnl It now puts everything required for sockets into LIB_SOCKET

AC_DEFUN([CMU_SOCKETS], [
        save_LIBS="$LIBS"
        LIB_SOCKET=""
        AC_CHECK_FUNC(connect, :,
                AC_CHECK_LIB(nsl, gethostbyname,
                             LIB_SOCKET="-lnsl $LIB_SOCKET")
                AC_CHECK_LIB(socket, connect,
                             LIB_SOCKET="-lsocket $LIB_SOCKET")
        )
        LIBS="$LIB_SOCKET $save_LIBS"
        AC_CHECK_FUNC(res_search, :,
                AC_CHECK_LIB(resolv, res_search,
                              LIB_SOCKET="-lresolv $LIB_SOCKET")
        )
        LIBS="$LIB_SOCKET $save_LIBS"
        AC_CHECK_FUNCS(dn_expand dns_lookup)
        LIBS="$save_LIBS"
        AC_SUBST(LIB_SOCKET)
        ])

dnl
dnl Require GeoIP
dnl Look for GeoIP distribution.
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_GEOIP(geoipdep, incls)
dnl
dnl results:
dnl
dnl   $1 (geoipdep set)
dnl   $2 (incls appended)
dnl   LIBS
dnl

AC_DEFUN([AC_QOSIENT_GEOIP], [
   AC_ARG_WITH(GeoIP,
            [AC_HELP_STRING([--with-GeoIP=DIR],[Compile with GeoIP in <DIR>])],
            with_geoip="$withval",
            with_geoip="yes")
   dnl
   dnl save a copy before locating libGeoIP.la
   dnl

   geoip=FAIL
   lastdir=FAIL

   if ! test ${with_geoip} = "no"; then
      if test ${with_geoip} = "yes"; then
         AC_CHECK_LIB(GeoIP, GeoIP_open, geoip="-GeoIP")
         if test $geoip = FAIL ; then
            AC_MSG_CHECKING(for standard GeoIP installation)
            for dir in /usr/local ; do
               if test -r $dir/lib/libGeoIP.a ; then
                   geoip=$dir/lib
                   AC_MSG_RESULT($geoip)
                   $1="-L$geoip -lGeoIP"
                   AC_MSG_CHECKING(for specified GeoIP.h)
                   if test -r $dir/include/GeoIP.h; then
                      d=$dir/include
                      AC_MSG_RESULT(found)
                      $2="-I$d $$2"
                   else
                      AC_MSG_RESULT(no)
                   fi
                   dnl continue and select the last one that exists
               else
                  AC_MSG_RESULT(no)
               fi
            done

            if test $geoip = FAIL; then
               AC_MSG_CHECKING(for local GeoIP library and includes)
               places=`ls $srcdir/.. | sed -e 's,/$,,' -e "s,^,$srcdir/../," | \
                  egrep '/GeoIP-[[0-9]]*.[[0-9]]*(.[[0-9]]*)?([[ab]][[0-9]]*)?$'`

               for dir in $places ; do
                  basedir=`echo $dir | sed -e 's/[[ab]][[0-9]]*$//'`
                  if test $lastdir = $basedir ; then
                      dnl skip alphas when an actual release is present
                      continue;
                  fi
                  lastdir=$dir
                  if test -r $dir/libGeoIP/.libs/libGeoIP.a ; then
                     if test -r $dir/libGeoIP/GeoIP.h ; then
                         geoip=$dir/libGeoIP/.libs
                         d=$dir/libGeoIP
                     fi
                     dnl continue and select the last one that exists
                  fi
               done
               if ! test $geoip = FAIL; then
                  AC_MSG_RESULT($geoip)
                  $1="-L$geoip -lGeoIP"
                  $2="-I$d $$2"
               else
                  AC_MSG_RESULT(no)
               fi
            fi
         else
            $1="-lGeoIP"
         fi
      fi

      if test $geoip = FAIL; then
         AC_MSG_CHECKING(for GeoIP library)
         for dir in ${with_geoip}; do
            if test -r $dir/lib/libGeoIP.a ; then
                geoip=$dir/lib
                AC_MSG_RESULT($geoip)
                $1="-L$geoip -lGeoIP"
                AC_MSG_CHECKING(for specified GeoIP.h)
                if test -r $dir/include/GeoIP.h; then
                   d=$dir/include
                   AC_MSG_RESULT(found)
                   $2="-I$d $$2"
                fi
                dnl continue and select the last one that exists
            fi
         done
         if test $geoip = FAIL; then
            AC_MSG_RESULT(not found)
         fi
      fi
         
      if ! test $geoip = FAIL; then
         AC_DEFINE([ARGUS_GEOIP], [], [Description])
      fi
   fi
])

dnl
dnl Look for Perl distribution and executable.
dnl
dnl usage:
dnl
dnl   AC_QOSIENT_PERL(perldep)
dnl
dnl results:
dnl
dnl   $1 (geoipdep set)
dnl

AC_DEFUN([AC_QOSIENT_PERL], [
   AC_ARG_WITH(perl,
            [AC_HELP_STRING([--with-perl=DIR],[Use perl in <DIR>])],
            with_perl="$withval",
            with_perl="yes")

   perl=FAIL

   if ! test ${with_perl} = "no"; then
      if test ${with_perl} = "yes"; then
         AC_MSG_CHECKING(for standard perl installation)
         for dir in /usr /usr/local /opt /opt/local; do
            if test -r $dir/bin/perl ; then
                perl=$dir/bin/perl
                AC_MSG_RESULT($perl)
                $1="$perl"
                break;
            else
               AC_MSG_RESULT(no)
            fi
         done
      else
         AC_MSG_CHECKING(for perl installation in ${with_perl})
         if test -r ${with_perl}/perl ; then
            perl=${with_perl}/perl
            AC_MSG_RESULT($perl)
            $1="$perl"
         else
            AC_MSG_RESULT(no)
         fi
      fi
   fi
])
