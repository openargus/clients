/* $Id: fatal.h,v 1.1 2004/05/12 00:04:26 qosient Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __FATAL_H__
#define __FATAL_H__


/*
 * in debugging mode print out the filename and the line number where the
 * failure have occured
 */


#ifdef DEBUG
	#define	FATAL(msg) 	{ printf("%s:%d: ", __FILE__, __LINE__); ArgusLog(LOG_ERR,(char *) msg); }
#else
	#define	FATAL(msg)	ArgusLog(LOG_ERR, (char *) msg)
#endif



#endif	/* __FATAL_H__ */
