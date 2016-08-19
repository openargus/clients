%define name    argus-clients
%define ver     3.0
%if %{?rel:0}%{!?rel:1}
%define rel     8.2
%endif
%if %{?srcext:0}%{!?srcext:1}
%define srcext .gz
%endif
Summary: Argus Client Software
Name: argus-clients
Version: %ver
Release: %rel
License: see COPYING file
Group: Applications/Internet
Source: %{name}-%{version}.%{rel}.tar%{srcext}
URL: http://qosient.com/argus
Buildroot: %{_tmppath}/%{name}-%{ver}-root

%description
Argus Clients contains a number of programs that process Argus data.
Copyright: 2000-2016 QoSient, LLC

%define argusdir        /usr
%define argusman        /usr/share/man
%define argusdocs       /usr/share/doc/%{name}-%{ver}

%define argusbin        %{argusdir}/bin
%define argussbin       %{argusdir}/sbin
%define argusinc        %{argusdir}/include
%define arguslib        %{argusdir}/lib
%define argusdata       %{argusdir}/argus

%prep
%setup -n %{name}-%{ver}.%{rel}
%build
./configure --prefix=/usr
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR="$RPM_BUILD_ROOT" install

install -D -m 0600 pkg/radium.conf $RPM_BUILD_ROOT/etc/radium.conf
install -D -m 0644 pkg/rhel/sysconfig/radium $RPM_BUILD_ROOT/etc/sysconfig/radium
install -D -m 0755 pkg/rhel/init.d/radium $RPM_BUILD_ROOT/etc/rc.d/init.d/radium

install -D -m 0644 pkg/rhel/sysconfig/rasplit $RPM_BUILD_ROOT/etc/sysconfig/rasplit
install -D -m 0755 pkg/rhel/init.d/rasplit $RPM_BUILD_ROOT/etc/rc.d/init.d/rasplit
install -d -m 0755 $RPM_BUILD_ROOT/%{argusdocs}/support
cp -av support $RPM_BUILD_ROOT/%{argusdocs}/

%post

%preun

%postun

%files
%defattr(-,root,root)

%{argusdata}/delegated-ipv4-latest
%{argusdata}/wireshark.manuf.txt
%{argusdata}/rarc

%doc %{argusdocs}

%{argusinc}/argus

%{arguslib}/argus_client.a
%{arguslib}/argus_common.a
%{arguslib}/argus_parse.a
%{arguslib}/pkgconfig/argus-clients.pc

%{argusman}/man1/ra.1.gz
%{argusman}/man1/rabins.1.gz
%{argusman}/man1/racluster.1.gz
%{argusman}/man1/raconvert.1.gz
%{argusman}/man1/racount.1.gz
%{argusman}/man1/radecode.1.gz
%{argusman}/man1/radump.1.gz
%{argusman}/man1/raevent.1.gz
%{argusman}/man1/rafilteraddr.1.gz
%{argusman}/man1/ragraph.1.gz
%{argusman}/man1/ragrep.1.gz
%{argusman}/man1/rahisto.1.gz
%{argusman}/man1/ralabel.1.gz
%{argusman}/man1/ranonymize.1.gz
%{argusman}/man1/rapath.1.gz
%{argusman}/man1/rapolicy.1.gz
%{argusman}/man1/rasort.1.gz
%{argusman}/man1/rasplit.1.gz
%{argusman}/man1/rasql.1.gz
%{argusman}/man1/rasqlinsert.1.gz
%{argusman}/man1/rasqltimeindex.1.gz
%{argusman}/man1/rastream.1.gz
%{argusman}/man1/rastrip.1.gz
%{argusman}/man1/ratop.1.gz
%{argusman}/man5/ranonymize.5.gz
%{argusman}/man5/rarc.5.gz
%{argusman}/man5/racluster.5.gz
%{argusman}/man5/racolor.conf.5.gz
%{argusman}/man5/ralabel.conf.5.gz
%{argusman}/man5/radium.conf.5.gz
%{argusman}/man8/radium.8.gz

%{argusbin}/argusclientbug
%{argusbin}/ra
%{argusbin}/rabins
%{argusbin}/racluster
%{argusbin}/raconvert
%{argusbin}/racount
%{argusbin}/radark
%{argusbin}/radecode
%{argusbin}/radump
%{argusbin}/raevent
%{argusbin}/rafilteraddr
%{argusbin}/ragraph
%{argusbin}/ragrep
%{argusbin}/rahisto
%{argusbin}/rahosts
%{argusbin}/ralabel
%{argusbin}/ranonymize
%{argusbin}/rapath
%{argusbin}/rapolicy
%{argusbin}/raports
%{argusbin}/rarpwatch
%{argusbin}/raservices
%{argusbin}/rasort
%{argusbin}/rasplit
%{argusbin}/rasql
%{argusbin}/rasqlinsert
%{argusbin}/rasqltimeindex
%{argusbin}/rastream
%{argusbin}/rastrip
%{argusbin}/ratemplate
%{argusbin}/ratimerange
%{argusbin}/ratop
%{argusbin}/rauserdata

%{argussbin}/radium
/etc/rc.d/init.d/radium 
/etc/rc.d/init.d/rasplit 

%config /etc/radium.conf
%config /etc/sysconfig/radium
%config /etc/sysconfig/rasplit
