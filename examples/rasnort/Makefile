# 
#  Argus Software
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# 
#
# Various configurable paths (remember to edit Makefile.in, not Makefile)
#
#  $Id: //depot/argus/clients/clients/Makefile.in#34 $
#  $DateTime: 2011/06/27 16:08:26 $
#  $Change: 2204 $
#  


# Top level hierarchy

prefix = /usr
exec_prefix = ${prefix}
datarootdir = ${prefix}/share

# Pathname of directory to install the system binaries
SBINDIR = ${exec_prefix}/sbin
# Pathname of directory to install the system binaries
BINDIR = ${exec_prefix}/bin
# Pathname of directory to install the include files
INCLDEST = ${prefix}/include
# Pathname of directory to install the library
LIBDEST =  ${exec_prefix}/lib
# Pathname of directory to install the man page
MANDEST = ${datarootdir}/man

# Pathname of preferred perl to use for perl scripts
PERL = /usr/bin/perl

# VPATH
srcdir = .


#
# You shouldn't need to edit anything below.
#

CC = gcc
CCOPT = -g  -Wall -Wmissing-prototypes
INCLS = -I. -I../../include -I../../common  
DEFS = -DHAVE_CONFIG_H
COMPATLIB = -lm   -lpthread    -lz

# Standard CFLAGS
CFLAGS = $(CCOPT) $(INCLS) $(DEFS) $(EXTRA_CFLAGS)

INSTALL    = /bin/install -c
INSTALLBIN = ../../bin
INSTALLLIB = ../../lib
RANLIB     = ranlib

#
# Flex and bison allow you to specify the prefixes of the global symbols
# used by the generated parser.  This allows programs to use lex/yacc
# and link against libpcap.  If you don't have flex or bison, get them.
#
LEX = flex -Pargus_
YACC = bison -y -p argus_

# Explicitly define compilation rule since SunOS 4's make doesn't like gcc.
# Also, gcc does not remove the .o before forking 'as', which can be a
# problem if you don't own the file but can write to the directory.
.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $(srcdir)/$*.c

LIB = $(INSTALLLIB)/argus_parse.a $(INSTALLLIB)/argus_common.a $(INSTALLLIB)/argus_client.a

SRC = rasnort.c parser.c signature.c

# We would like to say "OBJ = $(SRC:.c=.o)" but Ultrix's make cannot
# hack the extra indirection

OBJ =	$(SRC:.c=.o)

PROGS = $(INSTALLBIN)/rasnort

all: $(PROGS)

$(INSTALLBIN)/rasnort: $(OBJ) $(LIB)
	$(CC) $(CCOPT) -o $@ $(OBJ) $(LIB) $(COMPATLIB)

CLEANFILES = $(OBJ) $(PROGS)

install: force all
	[ -d $(DESTDIR)$(BINDIR) ] || \
		(mkdir -p $(DESTDIR)$(BINDIR); chmod 755 $(DESTDIR)$(BINDIR))
	$(INSTALL) $(INSTALLBIN)/ragrep $(DESTDIR)$(BINDIR)

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) Makefile config.cache config.log config.status \
	    gnuc.h os-proto.h bpf_filter.c net

tags: $(TAGFILES)
	ctags -wtd $(TAGFILES)

tar:	force
	@cwd=`pwd` ; dir=`basename $$cwd` ; name=libpcap-`cat VERSION` ; \
	    list="" ; tar="tar chFFf" ; \
	    for i in `cat FILES` ; do list="$$list $$name/$$i" ; done; \
	    echo \
	    "rm -f ../$$name; ln -s $$dir ../$$name" ; \
	     rm -f ../$$name; ln -s $$dir ../$$name ; \
	    echo \
	    "(cd .. ; $$tar - [lots of files]) | compress > /tmp/$$name.tar.Z" ; \
	     (cd .. ; $$tar - $$list) | compress > /tmp/$$name.tar.Z ; \
	    echo \
	    "rm -f ../$$name" ; \
	     rm -f ../$$name

force:	/tmp
depend:	$(GENSRC) force
	../../bin/mkdep -c $(CC) $(DEFS) $(INCLS) $(SRC)
