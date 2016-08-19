#!/bin/bash
#  Argus Client Support Software.  Tools to support tools for Argus data.
#  Copyright (C) 2000-2016 QoSient, LLC.
#  All Rights Reserved
#
#  ragetcountrycodes.sh
#
#  Script to get all the delegated address space allocations directly
#  from the proper registries and consolidate for ra* support for
#  printing country codes.
#  
#  This should be done periodcially, say weekly as the delegated
#  address space does change.
#
#  Carter Bullard <carter@qosient.com>
#

wget http://ftp.apnic.net/stats/arin/delegated-arin-extended-latest
wget http://ftp.apnic.net/stats/afrinic/delegated-afrinic-latest
wget http://ftp.apnic.net/stats/apnic/delegated-apnic-latest
wget http://ftp.apnic.net/stats/lacnic/delegated-lacnic-latest
wget http://ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest
wget http://ftp.apnic.net/stats/iana/delegated-iana-latest

fgrep ipv4 delegated-[alr]*-latest delegated-iana-latest > delegated-ipv4-latest
rm delegated-[alr]*-latest delegated-iana-latest
