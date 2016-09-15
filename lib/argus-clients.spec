%define name    argus-clients
%define ver     5.0
%if %{?rel:0}%{!?rel:1}
%define rel     3
%endif
%if %{?srcext:0}%{!?srcext:1}
%define srcext .gz
%endif
Summary: Gargoyle Client Software
Name: argus-clients
Version: %ver
Release: %rel
License: Proprietary
Group: Applications/Internet
Source: %{name}-%{version}.%{rel}.tar%{srcext}
URL: http://qosient.com/argus
Buildroot: %{_tmppath}/%{name}-%{ver}-root
BuildRequires: ncurses-devel, readline-devel, zlib-devel
BuildRequires: pcre-devel, GeoIP-devel
BuildRequires: mariadb-devel
BuildRequires: cyrus-sasl-devel
Requires: cyrus-sasl

%description
Argus Clients contains a number of programs that process Argus data.
Copyright: 2000-2022 QoSient, LLC

%define argusdir        /usr
%define argusman        /usr/share/man
%define argusdocs       /usr/share/doc/%{name}-%{ver}

%define argusbin        %{argusdir}/bin
%define argussbin       %{argusdir}/sbin
%define argusdata       %{argusdir}/argus

%prep
%setup -n %{name}-%{ver}.%{rel}
%build
./configure --prefix=/usr --with-sasl
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR="$RPM_BUILD_ROOT" install

install -D -m 0600 pkg/radium.conf $RPM_BUILD_ROOT/etc/radium.conf
install -D -m 0644 pkg/rhel/sysconfig/radium $RPM_BUILD_ROOT/etc/sysconfig/radium

install -D -m 0644 pkg/rhel/sysconfig/rasplit $RPM_BUILD_ROOT/etc/sysconfig/rasplit
install -D -m 0644 pkg/rhel/systemd/radium.service $RPM_BUILD_ROOT%{_unitdir}/radium.service
install -D -m 0644 pkg/rhel/systemd/rasplit.service $RPM_BUILD_ROOT%{_unitdir}/rasplit.service
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

%{argusman}/man1/ra.1.gz
%{argusman}/man1/rabins.1.gz
%{argusman}/man1/racluster.1.gz
%{argusman}/man1/racount.1.gz
%{argusman}/man5/radium.conf.5.gz
%{argusman}/man8/radium.8.gz
%{argusman}/man1/ranonymize.1.gz
%{argusman}/man1/rasort.1.gz
%{argusman}/man1/rasplit.1.gz

%{argusbin}/ra
%{argusbin}/rabins
%{argusbin}/racluster
%{argusbin}/racount
%{argusbin}/ranonymize
%{argusbin}/rasort
%{argusbin}/rasplit
%{argussbin}/radium
%{_unitdir}/radium.service
%{_unitdir}/rasplit.service

%config /etc/radium.conf
%config /etc/sysconfig/radium
%config /etc/sysconfig/rasplit


%package examples
Summary: Argus Client Example Programs
Group: Applications/Internet
Requires: cyrus-sasl

%description examples
argus-client-examples contains the compiled examples from the source
distribution.

%files examples
%defattr(-,root,root)
%{argusbin}/*
%exclude %{argusbin}/ra
%exclude %{argusbin}/rabins
%exclude %{argusbin}/racluster
%exclude %{argusbin}/racount
%exclude %{argusbin}/ranonymize
%exclude %{argusbin}/rasort
%exclude %{argusbin}/rasplit
%exclude %{argusbin}/ragraph
%exclude %{argusbin}/rasql*
%{argusman}
%exclude %{argusman}/man1/ra.1.gz
%exclude %{argusman}/man1/rabins.1.gz
%exclude %{argusman}/man1/racluster.1.gz
%exclude %{argusman}/man1/racount.1.gz
%exclude %{argusman}/man5/radium.conf.5.gz
%exclude %{argusman}/man8/radium.8.gz
%exclude %{argusman}/man1/ranonymize.1.gz
%exclude %{argusman}/man1/rasort.1.gz
%exclude %{argusman}/man1/rasplit.1.gz
%exclude %{argusman}/man1/ragraph.1.gz
%exclude %{argusman}/man1/rasql.1.gz


%package devel
Summary: Argus Client Software Development Libraries
Group: Applications/Internet

%description devel
Argus Clients contains a number of programs that process Argus data.
Copyright 2000-2016 QoSient, LLC

%define argusinc        %{argusdir}/include
%define arguslib        %{argusdir}/lib

%files devel
%defattr(-,root,root)
%{argusinc}/argus
%{arguslib}/argus_client.a
%{arguslib}/argus_common.a
%{arguslib}/argus_parse.a
%{arguslib}/pkgconfig/argus-clients.pc

%package graph
Summary: Argus Client Software Graph Tool
Group: Applications/Internet
Requires: argus-clients

%description graph
Tool to graph Argus data
Copyright 2000-2016 QoSient, LLC

%files graph
%defattr(-,root,root)
%{argusbin}/ragraph
%{argusman}/man1/ragraph.1.gz

%package sql
Summary: Argus Client Software SQL Tools
Group: Applications/Internet
Requires: argus-clients, mariadb-libs

%description sql
Tools to view modify Argus data in SQL databases
Copyright 2000-2016 QoSient, LLC

%files sql
%defattr(-,root,root)
%{argusbin}/rasql*
%{argusman}/man1/rasql*

%changelog
