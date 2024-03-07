/* $Id: spp_portscan2.h,v 1.8 2003/10/20 15:03:38 chrisgreen Exp $ */
/*
** Copyright (C) 1998,1999,2000,2001 Martin Roesch <roesch@clark.net>
** Copyright (C) 2001 Jed Haile <jhaile@nitrodata.com>
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
 
/* Hogwash Scan Munge plugin
   by Jed Haile <jhaile@nitrodata.com>
*/

#ifndef __SPP_SCANMUNGE_H__
#define __SPP_SCANMUNGE_H__

#include "snort.h"

void SetupScan2(void);
void psWatch(Packet *);
void SetupScanIgnoreHosts(void);

#endif
