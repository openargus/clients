/*
** $Id: bitop.h,v 1.1.2.3 2004/02/25 16:52:52 jh8 Exp $
** 
** bitopt.c
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
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
**
** NOTES
**   5.15.02 - Initial Source Code. Norton/Roelker
**   5.23.02 - Moved bitop functions to bitop.h to inline. Norton/Roelker
**   1.21.04 - Added static initialization. Roelker
** 
*/

#ifndef _BITOP_H
#define _BITOP_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifdef WIN32
#ifndef INLINE
#define INLINE __inline
#endif

#else

#ifndef INLINE
#define INLINE inline
#endif
#endif

typedef struct _BITOP {
    unsigned char *pucBitBuffer;
    unsigned int  uiBitBufferSize;
    unsigned int  uiMaxBits;
} BITOP;

/*
**  NAME
**    boInitStaticBITOP::
*/
/**
**  This function is for use if you handle the bitop buffer allocation
**  yourself.  Just pass in the char array and the number of bytes the array
**  is and this function sets up the structure for you.
**
**  @retval int
**
**  @return  0  successful
**  @return !0  failed
*/
static INLINE int boInitStaticBITOP(BITOP *BitOp,int iBytes,unsigned char *buf)
{
    if(iBytes < 1 || !buf || !BitOp)
        return 1;

    BitOp->pucBitBuffer   = buf;
    BitOp->uiBitBufferSize = (unsigned int)iBytes;
    BitOp->uiMaxBits       = (unsigned int)(iBytes << 3);

    memset(buf, 0x00, iBytes);

    return 0;
}

/*
**
**  NAME
**    boInitBITOP
**
**  DESCRIPTION
**    Initializes the BITOP structure for use.
**
**    NOTE:
**    BITOP structure must be zeroed to avoid misinterpretation
**    of initialization.
**
**  FORMAL INPUTS
**    BITOP * - the structure to initialize
**    int     - the number of bit positions to hold.
**
**  FORMAL OUTPUTS
**    int - 0 if successful, 1 if failed.
**
*/
static INLINE int boInitBITOP(BITOP *BitOp, int iSize)
{
    int iBytes;

    /*
    **  Sanity check for size
    */
    if(iSize < 1)
    {
        return 1;
    }

    /*
    **  Check for already initialized buffer, and
    **  if it is already initialized then we return that it
    **  is initialized.
    */
    if(BitOp->pucBitBuffer)
    {
        return 0;
    }

    iBytes = iSize >> 3;
    if(iSize & 7) 
    {
        iBytes++;
    }

    BitOp->pucBitBuffer = (unsigned char  *)calloc(1, iBytes);
    if(BitOp->pucBitBuffer == NULL)
    {
        return 1;
    }

    BitOp->uiBitBufferSize = (unsigned int)iBytes;
    BitOp->uiMaxBits       = (unsigned int)iSize;

    return 0;
}

/*
**
**  NAME
**    boResetBITOP
**
**  DESCRIPTION
**    This resets the bit buffer so that it can be used again.
**
**  FORMAL INPUTS
**    BITOP * - structure to reset
**
**  FORMAL OUTPUT
**    int - 0 if successful, 1 if failed.
**
*/
static INLINE int boResetBITOP(BITOP *BitOp)
{
    memset(BitOp->pucBitBuffer, 0x00, BitOp->uiBitBufferSize);
    return 0;
}

/*
**
**  NAME
**    boSetBit
**
**  DESCRIPTION
**    Set the bit in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to set within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the bit was set, 1 if there was an error.
**
*/
static INLINE int boSetBit(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while setting bits
    */
    if(BitOp->uiMaxBits <= uiPos)
    {
        return 1;
    }

    mask = 0x80 >> (uiPos & 7);

    BitOp->pucBitBuffer[uiPos >> 3] |= mask;

    return 0;
}
/*
**
**  NAME
**    boIsBitSet
**
**  DESCRIPTION
**    Checks for the bit set in iPos of bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - structure that holds the bit buffer
**    int     - the position number in the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if bit not set, 1 if bit is set.
**
*/
static INLINE int boIsBitSet(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while setting bits
    */
    if(BitOp->uiMaxBits <= uiPos)
    {
        return 0;
    }

    mask = 0x80 >> (uiPos & 7);

    return (mask & BitOp->pucBitBuffer[uiPos >> 3]);
}

/*
**
**  NAME
**    boClearBit
**
**  DESCRIPTION
**    Clear the bit in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to clear within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the bit was cleared, 1 if there was an error.
**
*/
static INLINE void boClearBit(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while clearing bits
    */
    if(BitOp->uiMaxBits <= uiPos)
    {
        return ;
    }

    mask = 0x80 >> (uiPos & 7);

    BitOp->pucBitBuffer[uiPos >> 3] &= ~mask;
}

/*
**
**  NAME
**    boClearByte
**
**  DESCRIPTION
**    Clear the byte in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to clear within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the byte was cleared, 1 if there was an error.
**
*/
static INLINE void boClearByte(BITOP *BitOp, unsigned int uiPos)
{
    /*
    **  Sanity Check while clearing bytes
    */
    if(BitOp->uiMaxBits <= uiPos)
    {
        return ;
    }

    BitOp->pucBitBuffer[uiPos >> 3] = 0;
}

#endif
