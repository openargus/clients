#!/bin/bash
#  Argus Client Support Software.  Tools to support tools for Argus data.
#  Copyright (c) 2000-2016 QoSient, LLC
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
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
#
#  MySQL.Archive.sh - This program moves argus data from a standard MySQL
#      archive to a standard native file system archive, and indexes for
#      time. Standard implies that the database table and the native file
#      system repository have the datetime as a part of its name.
#
#      This program is intended to provide repository migration for formal
#      data rention policies.  The notion is that you'll have data in the
#      database for some period of time, and then you will want to move the
#      primitive data, so that its available, but not within the RDMBS.
#
#      The database repository should have been created using rasqlinsert(),
#      and have the 'record' attribute in its schema definition.  This is
#      the actual argus record that will be inserted into the native file
#      system archive.  rasql() will read the data from the data base,
#      and pipe its output to rasplit() which will populate the native
#      file system archive.
#
#      You will need to set these variables to your liking:
#         MYSQL_USER="the mysql account that has permissions on the table"
#         MYSQL_HOST="the host where mysql runs"
#         MYSQL_DATABASE="the mysql database name"
#         MYSQL_TABLE="the table name, the script will add the data string to the end"
#
#         ARCHIVE_FILESYSTEM="/Path/To/The/Argus/Archive"
#
#  Carter Bullard <carter@qosient.com>
#

RASQL=/usr/local/bin/rasql
RASQLTIMEINDEX=/usr/local/bin/rasqltimeindex
MYSQL=/usr/local/mysql/bin/mysql
MYSQL_USER="user"
MYSQL_HOST="host"
MYSQL_DATABASE="db"
MYSQL_TABLE="table"

ARCHIVE_FILESYSTEM="/Path/To/The/Argus/Archive"
ARCHIVE_FORMAT="\$srcid/%Y/%m/%d/argus.%Y.%m.%d.%H.%M.%S"
ARCHIVE_PERIOD="-M time 5m"

ARCHIVE_DATE=""
ARCHIVE_PATH=""
ARCHIVE_RETENTION_DAYS=30

MYSQL_COMMAND="$RASQL -r mysql://$MYSQL_USER@$MYSQL_HOST/$MYSQL_DATABASE"
MYSQL_INDEX="$RASQLTIMEINDEX -w mysql://$MYSQL_USER@$MYSQL_HOST/$MYSQL_DATABASE"

RASPLIT="/usr/local/bin/rasplit"
RASPLIT_COMMAND="$RASPLIT $ARCHIVE_PERIOD -w $ARCHIVE_FILESYSTEM/$ARCHIVE_FORMAT"

set_archive_date() {
   set -- $(TZ=GMT date '+%Y %m %d')
   local y=$1 m=1$2 d=1$3
   ((m-=103, d-=101, m<0 && (m+=12, --y)))
   ((d+=((m*153 + 2)/5+y*365+y/4-y/100+y/400)- 719468))
   ARCHIVE_DATE=`date -r $((d*86400 - $ARCHIVE_RETENTION_DAYS*86400)) +%Y_%m_%d`
   ARCHIVE_PATH=`date -r $((d*86400 - $ARCHIVE_RETENTION_DAYS*86400)) +%Y/%m/%d/argus.%Y.%m.%d`
}

set_archive_date;

ARCHIVE_COMMAND="$MYSQL_COMMAND/$MYSQL_TABLE"_"$ARCHIVE_DATE -w -"
DATABASE_COMMAND="drop table $MYSQL_TABLE"_"$ARCHIVE_DATE"

if [ "$ARCHIVE_DATE" != "" ]
then
   echo "$ARCHIVE_COMMAND | $RASPLIT_COMMAND"
   `$ARCHIVE_COMMAND | $RASPLIT_COMMAND`

   echo "$MYSQL_INDEX -r $ARCHIVE_FILESYSTEM/*/$ARCHIVE_PATH\*"
   `$MYSQL_INDEX -r $ARCHIVE_FILESYSTEM/*/$ARCHIVE_PATH\*`

   echo "echo 'mysql $DATABASE_COMMAND' | $MYSQL -u $MYSQL_USER $MYSQL_DATABASE"
   `echo $DATABASE_COMMAND | $MYSQL -u $MYSQL_USER $MYSQL_DATABASE`
else
   echo "error on date conversion"
fi
