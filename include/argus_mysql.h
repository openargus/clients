/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 *
 */

#ifndef ARGUS_MYSQL_H
# define ARGUS_MYSQL_H
# ifdef ARGUS_MYSQL
#  ifdef HAVE_STDBOOL_H
#   include <stdbool.h>
#  endif
#  include <mysql.h>
#  ifndef HAVE_MYSQL_MY_BOOL
#   define my_bool bool
#  endif
#  define RASQL_MAX_VARCHAR     128
# endif /* ARGUS_MYSQL*/
#endif /* ARGUS_MYSQL_H */
