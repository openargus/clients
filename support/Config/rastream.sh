#!/bin/sh
#  Argus Client Software.  Tools to read, analyze and manage Argus data.
#  Copyright (C) 2000-2016 QoSient, LLC.
#  All Rights Reserved
#
# Script called by rastream, to process files.
#
# Since this is being called from rastream(), it will have only a single
# parameter, filename,
#
# Carter Bullard <carter@qosient.com>
#

PATH="/usr/local/bin:$PATH"; export PATH
package="argus-clients"
version="3.0.2"

OPTIONS="$*"
FILES=
while  test $# != 0
do
    case "$1" in
    -r) shift; FILES="$1"; break;;
    esac
    shift
done

racluster -M replace -r $FILES
gzip $FILES
exit 0
