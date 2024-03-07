/**
**  @file       hi_norm.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com
**  
**  @brief      Contains normalization skeleton for server and client
**              normalization routines.
**  
**  This file contains the core routines to normalize the different fields
**  within the HTTP protocol.  We currently only support client URI
**  normalization, but the hooks are here to easily add other routines.
**  
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "hi_client_norm.h"
#include "hi_eo.h"
#include "hi_eo_events.h"
#include "hi_eo_log.h"
#include "hi_ui_iis_unicode_map.h"
#include "hi_return_codes.h"
#include "hi_si.h"
#include "hi_util.h"
#include "hi_util_xmalloc.h"

#define MAX_DIRS        2048

#define NO_HEX_VAL      -1
#define BASE36_VAL      -2
#define HEX_VAL          1

/**
**  This define checks for negative return codes, since we have multiple
**  reasons to error.  This just cuts the return code checks, especially
**  as we add more errors.
*/
#define GET_ERR         0x80000000
#define END_OF_BUFFER   -1
#define DOUBLE_ENCODING -2
#define DIR_TRAV        -2

#define NON_ASCII_CHAR  0xff

typedef int (*DECODE_FUNC)(HI_SESSION *, u_char *,
                          u_char *, u_char **);

typedef struct s_URI_NORM_STATE
{
    u_char *abs_uri;
    u_char *param;

    /*
    **  Directory tracking
    */
    u_char *dir_track[MAX_DIRS];
    u_int   dir_count;

}  URI_NORM_STATE;

static int hex_lookup[256];
static int valid_lookup[256];

/*
**  NAME
**    GetPtr::
*/
/**
**  This routine is for getting bytes in the U decode.
**  
**  This checks the current bounds and checking for the double decoding.
**  This routine differs from the other Get routines because it returns
**  other values than just END_OF_BUFFER and the char.
**  
**  We also return DOUBLE_ENCODING if there is a % and double decoding
**  is turned on.
**  
**  When using this function it is important to note that it increments
**  the buffer before checking the bounds.  So, if you call this function
**  in a loop and don't check for END_OF_BUFFER being returned, then 
**  you are going to overwrite the buffer.  If I put the check in, you
**  would just be in an never-ending loop.  So just use this correctly.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  
**  @return integer
**  
**  @retval END_OF_BUFFER    the end of the buffer has been reached.
**  @retval DOUBLE_ENCODING  a percent was found and double decoding is on
**  @retval <= 0xff          an ASCII char         
*/
static int GetPtr(HI_SESSION *Session, u_char *start,
                   u_char *end, u_char **ptr)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;

    (*ptr)++;

    if(!hi_util_in_bounds(start, end, *ptr))
        return END_OF_BUFFER;

    if(ServerConf->double_decoding.on && **ptr == '%')
        return DOUBLE_ENCODING;

    return (int)**ptr;
}

/*
**  NAME
**    UDecode::
*/
/**
**  Handles the single decode for %U encoding.
**  
**  This routine receives the ptr pointing to the u.  We check the bounds
**  and continue with processing.  %u encoding works by specifying the
**  exact codepoint to be used.  For example, %u002f would be /.  So this
**  all seems fine.  BUT, the problem is that IIS maps multiple codepoints
**  to ASCII characters.  So, %u2044 also maps to /.  So this is what we
**  need to handle here.
**  
**  This routine only handles the single encoding.  For double decoding,
**  %u is handled in DoubleDecode().  It's the same routine, with just
**  the GetByte function different.
**  
**  We use a get_byte function to get the bytes, so we can use this
**  routine for PercentDecode and for DoubleDecode.
**
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  @param get_byte    the function pointer to get bytes.
**  
**  @return integer
**  
**  @retval END_OF_BUFFER    we are at the end of the buffer
**  @retval DOUBLE_ENCODING  this U encoding is possible double encoded
**  @retval NON_ASCII_CHAR   return this char for non-ascii or bad decodes
**  @retval iChar            this is the char that we decoded.
*/
static int UDecode(HI_SESSION *Session, u_char *start,
                   u_char *end, u_char **ptr, DECODE_FUNC get_byte)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iByte;
    int iNorm;
    int iCtr;

    iNorm = 0;

    for(iCtr = 0; iCtr < 4; iCtr++)
    {
        iByte = get_byte(Session, start, end, ptr);
        if(iByte & GET_ERR)
            return iByte;

        if(valid_lookup[(u_char)iByte] < 0)
            return NON_ASCII_CHAR;

        iNorm <<= 4;
        iNorm = (iNorm | (hex_lookup[(u_char)iByte]));
    }

    /*
    **  If the decoded codepoint is greater than a single byte value,
    **  then we return a NON_ASCII_CHAR.
    */
    if(iNorm > 0xff)
    {
        /*
        **  We check here for IIS codepoints that map to ASCII chars.
        */
        if(ServerConf->iis_unicode.on && iNorm <= 0xffff)
        {
            iNorm = ServerConf->iis_unicode_map[iNorm];

            if(iNorm == HI_UI_NON_ASCII_CODEPOINT)
            {
                iNorm = NON_ASCII_CHAR;
            }

            if(hi_eo_generate_event(Session, ServerConf->iis_unicode.alert))
            {
                hi_eo_client_event_log(Session, HI_EO_CLIENT_IIS_UNICODE,
                                       NULL, NULL);
            }
        }
        else
        {
            return NON_ASCII_CHAR;
        }
    }

    /*
    **  Check if we alert on this encoding
    */
    if(hi_eo_generate_event(Session, ServerConf->u_encoding.alert))
    {
        hi_eo_client_event_log(Session, HI_EO_CLIENT_U_ENCODE,
                                         NULL, NULL);
    }

    return iNorm;
}

/*
**  NAME
**    PercentDecode::
*/
/**
**  This is the first level of decoding, and deals with ASCII, U, and
**  double decoding.
**
**  This function is the main decoding function.  It handles all the ASCII
**  encoding and the U encoding, and tells us when there is a double
**  encoding.
**  
**  We use the GetPtr() routine to get the bytes for us.  This routine
**  checks for DOUBLE_ENCODING and tells us about it if it finds something,
**  so we can reset the ptrs and run it through the double decoding
**  routine.
**  
**  The philosophy behind this routine is that if we run out of buffer
**  we return such, the only other thing we return besides the decodes
**  char is a NON_ASCII_CHAR in the case that we try and decode something
**  like %tt.  This is no good, so we return a place holder.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  
**  @return integer
**  
**  @retval END_OF_BUFFER   We've hit the end of buffer while decoding.
**  @retval NON_ASCII_CHAR  Invalid hex encoding, so we return a placeholder.
**  @retval char            return the valid char
**  
**  @see GetPtr()
*/
static int PercentDecode(HI_SESSION *Session, u_char *start, 
                         u_char *end, u_char **ptr)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int    iByte;
    u_char *orig_ptr;
    int    iNorm;

    orig_ptr = *ptr;

    iByte = GetPtr(Session, start, end, ptr);
    if(iByte & GET_ERR)
    {
        if(iByte == END_OF_BUFFER)
            return END_OF_BUFFER;

        if(iByte == DOUBLE_ENCODING)
        {
            *ptr = orig_ptr;
            return (int)**ptr;
        }
    }

    /*
    **  Initialize the normalization byte
    */
    iNorm = 0;

    /*
    **  hex values
    */
    if(valid_lookup[(u_char)iByte] < 0)
    {
        /*
        **  Check for %u encoding.
        **
        **  The u-encoding loop always returns something.
        */
        if(ServerConf->u_encoding.on && (toupper(iByte) == 'U'))
        {
            iNorm = UDecode(Session, start, end, ptr, GetPtr);

            /*
            **  We have to handle the double meaning of END_OF_BUFFER
            **  when using the GetPtr() function.
            */
            if(iNorm & GET_ERR)
            {
                if(iNorm == END_OF_BUFFER)
                {
                    /*
                    **  We have reached the end of the buffer while
                    **  processing a U encoding.
                    */
                    return END_OF_BUFFER;
                }

                if(iNorm == DOUBLE_ENCODING)
                {
                    *ptr = orig_ptr;
                    return (int)**ptr;
                }
            }

            return iNorm;
        }
        else if(!ServerConf->base36.on ||
                valid_lookup[(u_char)iByte] != BASE36_VAL)
        {
            return NON_ASCII_CHAR;
        }

        /*
        **  The logic above dictates that if we get to this point, we
        **  have a valid base36 encoding, so let's log the event.
        */
        if(hi_eo_generate_event(Session, ServerConf->base36.alert))
        {
            hi_eo_client_event_log(Session, HI_EO_CLIENT_BASE36, NULL, NULL);
        }
    }

    iNorm = (hex_lookup[(u_char)iByte]<<4);
    iByte = GetPtr(Session, start, end, ptr);
    if(iByte & GET_ERR)
    {
        if(iByte == END_OF_BUFFER)
            return END_OF_BUFFER;

        if(iByte == DOUBLE_ENCODING)
        {
            *ptr = orig_ptr;
            return (int)**ptr;
        }
    }

    if(valid_lookup[(u_char)iByte] < 0)
    {
        if(!ServerConf->base36.on || valid_lookup[(u_char)iByte] != BASE36_VAL)
        {
            return NON_ASCII_CHAR;
        }

        /*
        **  Once again, we know we have a valid base36 encoding, let's alert
        **  if possible.
        */
        if(hi_eo_generate_event(Session, ServerConf->base36.alert))
        {
            hi_eo_client_event_log(Session, HI_EO_CLIENT_BASE36, NULL, NULL);
        }
    }

    iNorm = (iNorm | (hex_lookup[(u_char)iByte])) & 0xff;

    if(hi_eo_generate_event(Session,ServerConf->ascii.alert))
    {
        hi_eo_client_event_log(Session, HI_EO_CLIENT_ASCII,
                               NULL, NULL);
    }

    return iNorm;
}

/*
**  NAME
**    GetChar::
*/
/**
**  Wrapper for PercentDecode() and handles the return values from
**  PercentDecode().
**  
**  This really decodes the chars for UnicodeDecode().  If the char is
**  a percent then we process stuff, otherwise we just increment the
**  pointer and return.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  @param bare_byte   value for a non-ASCII char or a decoded non-ASCII char
**  
**  @return integer
**  
**  @retval END_OF_BUFFER   End of the buffer has been reached before decode.
**  @retval NON_ASCII_CHAR  End of buffer during decoding, return decoded char.
**  @retval char            return the valid decoded/undecoded char
**  
**  @see PercentDecode()
**  @see GetByte()
*/
static int GetChar(HI_SESSION *Session, u_char *start,
                   u_char *end, u_char **ptr, int *bare_byte)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iNorm = (int)(**ptr);

    if(!hi_util_in_bounds(start, end, *ptr))
        return END_OF_BUFFER;

    if(**ptr == '%' && ServerConf->ascii.on)
    {
        /*
        **  We go into percent encoding.
        */
        iNorm = PercentDecode(Session, start, end, ptr);

        /*
        **  If during the course of PercentDecode() we run into the end
        **  of the buffer, then we return early (WITHOUT INCREMENTING ptr)
        **  with a NON_ASCII_CHAR.
        */
        if(iNorm == END_OF_BUFFER)
            return NON_ASCII_CHAR;

        *bare_byte = 0;
    }
    else
    {
        if(ServerConf->bare_byte.on && (u_char)iNorm > 0x7f)
        {
            if(hi_eo_generate_event(Session, ServerConf->bare_byte.alert))
            {
                hi_eo_client_event_log(Session, HI_EO_CLIENT_BARE_BYTE,
                                       NULL, NULL);
            }

            /*
            **  Set the bare_byte flag
            */
            *bare_byte = 0;
        }
        else
        {
            /*
            **  Set the bare_byte flag negative.
            */
            *bare_byte = 1;
        }
    }

    /*
    **  Increment the buffer.
    */
    (*ptr)++;

    return iNorm;
}

/*
**  NAME
**    UTF8Decode::
*/
/**
**  Decode the UTF-8 sequences and check for valid codepoints via the
**  Unicode standard and the IIS standard.
**  
**  We decode up to 3 bytes of UTF-8 because that's all I've been able to
**  get to work on various servers, so let's reduce some false positives.
**  So we decode valid UTF-8 sequences and then check the value.  If the
**  value is ASCII, then it's decoded to that.  Otherwise, if iis_unicode
**  is turned on, we will check the unicode codemap for valid IIS mappings.
**  If a mapping turns up, then we return the mapped ASCII.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  
**  @return integer
**  
**  @retval NON_ASCII_CHAR  Reached end of buffer while decoding
**  @retval char            return the decoded or badly decoded char
**  
**  @see GetByte()
**  @see UnicodeDecode()
*/
static int UTF8Decode(HI_SESSION *Session, u_char *start,
                         u_char *end, u_char **ptr, int iFirst)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iBareByte;
    int iNorm;
    int iNumBytes;
    int iCtr;
    int iByte;

    /*
    **  Right now we support up to 3 byte unicode sequences.  We can add 
    **  more if any of the HTTP servers support more.
    */
    if((iFirst & 0xe0) == 0xc0)
    {
        iNumBytes = 1;
        iNorm = iFirst & 0x1f;
    }
    else if((iFirst & 0xf0) == 0xe0)
    {
        iNumBytes = 2;
        iNorm = iFirst & 0x0f;
    }
    else
    {
        /*
        **  This means that we have an invalid first sequence byte for
        **  a unicode sequence.  So we just return the byte and move on.
        */
        return iFirst;
    }

    /*
    **  This is the main loop for UTF-8 decoding.  We check for the only
    **  valid sequence after the first byte whish is 0x80.  Otherwise,
    **  it was invalid and we setnd a NON_ASCII_CHAR and continue on
    **  with our processing.
    */
    for(iCtr = 0; iCtr < iNumBytes; iCtr++)
    {
        iByte = GetChar(Session, start, end, ptr, &iBareByte);
        if(iByte == END_OF_BUFFER || iBareByte)
            return NON_ASCII_CHAR;

        if((iByte & 0xc0) == 0x80)
        {
            iNorm <<= 6;
            iNorm |= (iByte & 0x3f);
        }
        else
        {
            /*
            **  This means that we don't have a valid unicode sequence, so
            **  we just bail.
            */
            return NON_ASCII_CHAR;
        }
    }

    /*
    **  Check for unicode as ASCII and if there is not an ASCII char then
    **  we return the space holder char.
    */
    if(iNorm > 0x7f)
    {
        if(ServerConf->iis_unicode.on)
        {
            iNorm = ServerConf->iis_unicode_map[iNorm];

            if(iNorm == HI_UI_NON_ASCII_CODEPOINT)
            {
                iNorm = NON_ASCII_CHAR;
            }

            if(hi_eo_generate_event(Session, ServerConf->iis_unicode.alert))
            {
                hi_eo_client_event_log(Session, HI_EO_CLIENT_IIS_UNICODE,
                                       NULL, NULL);
            }

            return iNorm;
        }
        else
        {
            iNorm = NON_ASCII_CHAR;
        }
    }

    if(hi_eo_generate_event(Session, ServerConf->utf_8.alert))
    {
        hi_eo_client_event_log(Session, HI_EO_CLIENT_UTF_8,
                               NULL, NULL);
    }

    return iNorm;
}

/*
**  NAME
**    UnicodeDecode::
*/
/**
**  Checks for the ServerConf values before we actually decode.
**  
**  This function is really a ServerConf wrapper for UTF8Decode.
**
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  
**  @return integer
**  
**  @retval char       the decode/undecoded byte.
**  
**  @see GetByte()
*/
static int UnicodeDecode(HI_SESSION *Session, u_char *start, 
                         u_char *end, u_char **ptr, int iFirst)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iNorm = iFirst;

    if(ServerConf->iis_unicode.on || ServerConf->utf_8.on)
    {
        iNorm = UTF8Decode(Session, start, end, ptr, iFirst);
    }

    return iNorm;
}

/*
**  NAME
**    GetByte::
*/
/**
**  Handles the first stage of URI decoding for the case of IIS double
**  decoding.
**  
**  The first stage consists of ASCII decoding and unicode decoding.  %U
**  decoding is handled in the ASCII decoding.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  
**  @return integer
**  
**  @retval END_OF_BUFFER means that we've reached the end of buffer in
**                        GetChar.
**  @retval iChar         this is the character that was decoded.
*/
static int GetByte(HI_SESSION *Session, u_char *start, u_char *end,
                   u_char **ptr)
{
    int iChar;
    int iBareByte;

    iChar = GetChar(Session, start, end, ptr, &iBareByte);
    if(iChar == END_OF_BUFFER)
        return END_OF_BUFFER;

    /*
    **  We now check for unicode bytes
    */
    if((iChar & 0x80) && (iChar != NON_ASCII_CHAR) && !iBareByte)
    {
        iChar = UnicodeDecode(Session, start, end, ptr, iChar);
    }

    return iChar;
}

/*
**  NAME
**    DoubleDecode::
*/
/**
**  The double decoding routine for IIS good times.
**  
**  Coming into this function means that we just decoded a % or that
**  we just saw two percents in a row.  We know which state we are
**  in depending if the first char is a '%' or not.
**
**  In the IIS world, there are two decodes, but only some of the decode
**  options are valid.  All options are valid in the first decode
**  stage, but the second decode stage only supports:
**  -  %u encoding
**  -  ascii
**
**  Knowing this, we can decode appropriately.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  @param norm_state  the ptr to the URI norm state
**  
**  @return integer
**  
**  @retval NON_ASCII_CHAR  End of buffer reached while decoding
**  @retval char            The decoded char
*/
static int DoubleDecode(HI_SESSION *Session, u_char *start,
                        u_char *end, u_char **ptr,
                        URI_NORM_STATE *norm_state)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iByte;
    int iNorm;
    u_char *orig_ptr;

    orig_ptr = *ptr;

    /*
    **  We now know that we have seen a previous % and that we need to
    **  decode the remaining bytes.  We are in one of multiple cases:
    **
    **  -  %25xxxx
    **  -  %%xx%xx
    **  -  %u0025xxxx
    **  -  etc.
    **
    **  But, the one common factor is that they each started out with a
    **  % encoding of some type.
    **
    **  So now we just get the remaining bytes and do the processing
    **  ourselves in this routine.
    */
    iByte = GetByte(Session, start, end, ptr);
    if(iByte == END_OF_BUFFER)
        return NON_ASCII_CHAR;

    if(valid_lookup[(u_char)iByte] < 0)
    {
        if(ServerConf->u_encoding.on && (toupper(iByte) == 'U'))
        {
            iNorm = UDecode(Session, start, end, ptr, GetByte);
            
            if(iNorm == END_OF_BUFFER)
            {
                /*
                **  We have reached the end of the buffer while
                **  processing a U encoding.  We keep the current
                **  pointer and return a NON_ASCII char for the
                **  bad encoding.
                */
                return NON_ASCII_CHAR;
            }

            return iNorm;
        }

        return iByte;
    }

    iNorm = (hex_lookup[(u_char)iByte]<<4);

    iByte = GetByte(Session, start, end, ptr);
    if(iByte == END_OF_BUFFER)
        return NON_ASCII_CHAR;

    if(valid_lookup[(u_char)iByte] < 0)
    {
        return iByte;
    }

    iNorm = (iNorm | (hex_lookup[(u_char)iByte])) & 0xff;

    if(hi_eo_generate_event(Session, ServerConf->double_decoding.alert) &&
       (norm_state->param == NULL))
    {
        hi_eo_client_event_log(Session, HI_EO_CLIENT_DOUBLE_DECODE,
                               NULL, NULL);
    }

    return iNorm;
}

/*
**  NAME
**    GetDecodedByte::
*/
/**
**  This is the final GetByte routine.  The value that is returned from this
**  routine is the final decoded byte, and normalization can begin.  This
**  routine handles the double phase of decoding that IIS is fond of.
**  
**  So to recap all the decoding up until this point.
**  
**  The first phase is to call GetByte().  GetByte() returns the first stage
**  of decoding, which handles the UTF-8 decoding.  If we have decoded a
**  % of some type, then we head into DoubleDecode() if the ServerConf
**  allows it.
**  
**  What returns from DoubleDecode is the final result.
**  
**  @param ServerConf  the server configuration
**  @param start       the start of the URI
**  @param end         the end of the URI
**  @param ptr         the current pointer into the URI
**  @param norm_state  the pointer to the URI norm state
**  
**  @return integer
**  
**  @retval END_OF_BUFFER  While decoding, the end of buffer was reached.
**  @retval char           The resultant decoded char.
**  
**  @see DoubleDecode();
**  @see GetByte();
*/
static int GetDecodedByte(HI_SESSION *Session, u_char *start,
                          u_char *end, u_char **ptr, 
                          URI_NORM_STATE *norm_state)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iChar;

    iChar = GetByte(Session,start,end,ptr);
    if(iChar == END_OF_BUFFER)
        return END_OF_BUFFER;

    if(ServerConf->double_decoding.on && (u_char)iChar == '%')
    {
        iChar = DoubleDecode(Session,start,end,ptr, norm_state);
    }

    /*
    **  Let's change '\' to '/' if possible
    */
    if(ServerConf->iis_backslash.on && (u_char)iChar == 0x5c)
    {
        if(hi_eo_generate_event(Session, ServerConf->iis_backslash.alert))
        {
            hi_eo_client_event_log(Session, HI_EO_CLIENT_IIS_BACKSLASH, 
                                   NULL, NULL);
        }

        iChar = 0x2f;
    }

    return iChar;
}

/*
**  NAME
**    DirTrav::
*/
/**
**  Set the ub_ptr and update the URI_NORM_STATE.
**  
**  The main point of this function is to take care of the details in
**  updating the directory stack and setting the buffer pointer to the
**  last directory.
**  
**  @param norm_state pointer to the normalization state struct
**  @param ub_ptr     double pointer to the normalized buffer
**  
**  @return integer
**  
**  @retval HI_SUCCESS function successful
**  
**  @see hi_norm_uri()
*/
static int DirTrav(URI_NORM_STATE *norm_state,u_char *ub_start,u_char **ub_ptr)
{
    if(norm_state->dir_count)
    {
        *ub_ptr = norm_state->dir_track[norm_state->dir_count - 1];
        
        /*
        **  Check to make sure that we aren't at the beginning
        */
        if(norm_state->dir_count  > 1)
            norm_state->dir_count--;
    }
    else
    {
        /*
        **  This is a special case where there was no / seen before
        **  we see a /../.  When this happens, we just reset the ub_ptr
        **  back to the beginning of the norm buffer and let the slash
        **  get written on the next iteration of the loop.
        */
        *ub_ptr = ub_start;
    }

    return HI_SUCCESS; 
}

/*
**  NAME
**    DirSet::
*/
/**
**  Set the directory by writing a '/' to the normalization buffer and
**  updating the directory stack.
**  
**  This gets called after every slash that isn't a directory traversal.  We
**  just write a '/' and then update the directory stack to point to the
**  last directory, in the case of future directory traversals.
**  
**  @param norm_state pointer to the normalization state struct
**  @param ub_ptr     double pointer to the normalized buffer
**  
**  @return integer
**  
**  @retval HI_SUCCESS function successful
**  
**  @see hi_norm_uri()
*/
static int DirSet(URI_NORM_STATE *norm_state, u_char **ub_ptr)
{
    /*
    **  Write the '/'.  Even if iDir is the END_OF_BUFFER we still
    **  write it because the '/' came before the END_OF_BUFFER.
    */
    **ub_ptr = '/';

    if(!norm_state->param)
    {
        norm_state->dir_track[norm_state->dir_count] = *ub_ptr;
        if(norm_state->dir_count < MAX_DIRS)
            norm_state->dir_count++;
    }

    (*ub_ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    DirNorm::
*/
/**
**  The main function for dealing with multiple slashes, self-referential
**  directories, and directory traversals.
**  
**  This routine does GetDecodedByte() while looking for directory foo.  It's
**  called every time that we see a slash in the main hi_norm_uri.  Most of
**  the time we just enter this loop, find a non-directory-foo char and 
**  return that char.  hi_norm_uri() takes care of the directory state
**  updating and so forth.
**  
**  But when we run into trouble with directories, this function takes care
**  of that.  We loop through multiple slashes until we get to the next
**  directory.  We also loop through self-referential directories until we
**  get to the next directory.  Then finally we deal with directory 
**  traversals.
**  
**  With directory traversals we do a kind of "look ahead".  We verify that
**  there is indeed a directory traversal, and then set the ptr back to
**  the beginning of the '/', so when we iterate through hi_norm_uri() we
**  catch it.
**  
**  The return value for this function is usually the character after
**  the directory.  When there was a directory traversal, it returns the
**  value DIR_TRAV.  And when END_OF_BUFFER is returned, it means that we've
**  really hit the end of the buffer, or we were looping through multiple
**  slashes and self-referential directories until the end of the URI
**  buffer.
**  
**  @param ServerConf   pointer to the Server configuration
**  @param start        pointer to the start of the URI buffer
**  @param end          pointer to the end of the URI buffer
**  @param ptr          pointer to the index in the URI buffer
**  
**  @return integer
**  
**  @retval END_OF_BUFFER   we've reached the end of buffer
**  @retval DIR_TRAV        we found a directory traversal
**  @retval char            return the next char after the directory
**  
**  @see hi_norm_uri()
**  @see GetDecodedByte()
*/
static int DirNorm(HI_SESSION *Session, u_char *start, u_char *end,
                   u_char **ptr, URI_NORM_STATE *norm_state)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iChar;
    int iDir;
    u_char *orig_ptr;
    u_char *dir_ptr;

    while((iChar = GetDecodedByte(Session, start, end, ptr, norm_state)) !=
          END_OF_BUFFER)
    {
        orig_ptr = *ptr;

        /*
        **  This is kind of a short cut to get out of here as soon as we
        **  can.  If the character is over 0x2f then we know that is can't
        **  be either the '.' or the '/', so we break and return the
        **  char.
        */
        if((u_char)iChar < 0x30)
        {
            /*
            **  We check for multiple slashes.  If we find multiple slashes
            **  then we just continue on until we find something interesting.
            */
            if(ServerConf->multiple_slash.on && (u_char)iChar == '/')
            {
                if(hi_eo_generate_event(Session,
                                        ServerConf->multiple_slash.alert))
                {
                    hi_eo_client_event_log(Session,
                                           HI_EO_CLIENT_MULTI_SLASH,
                                           NULL, NULL);
                }

                continue;
            }
            /*
            **  This is where we start looking for self-referential dirs
            **  and directory traversals.
            */
            else if(ServerConf->directory.on && (u_char)iChar == '.' &&
                    !norm_state->param)
            {
                iDir = GetDecodedByte(Session,start,end,ptr,norm_state);
                if(iDir != END_OF_BUFFER)
                {
                    if((u_char)iDir == '.')
                    {
                        /*
                        **  This sets the dir_ptr to the beginning of the
                        **  byte that may be a dir.  So if it is a slash,
                        **  we can get back to that slash and continue
                        **  processing.
                        */
                        dir_ptr = *ptr;

                        iDir = GetDecodedByte(Session,start,end,ptr,norm_state);
                        if(iDir != END_OF_BUFFER)
                        {
                            if((u_char)iDir == '/')
                            {
                                /*
                                **  We found a real live directory traversal
                                **  so we reset the pointer to before the
                                **  '/' and finish up after the return.
                                */
                                if(hi_eo_generate_event(Session,
                                                 ServerConf->directory.alert))
                                {
                                    hi_eo_client_event_log(Session,
                                                         HI_EO_CLIENT_DIR_TRAV,
                                                         NULL, NULL);
                                }

                                *ptr = dir_ptr;
                                return DIR_TRAV;
                            }
                        }

                        *ptr = orig_ptr;
                        return iChar;
                    }
                    else if((u_char)iDir == '/')
                    {
                        /*
                        **  We got a self-referential directory traversal.
                        **
                        **  Keep processing until we stop seeing self
                        **  referential directories.
                        */
                        if(hi_eo_generate_event(Session,
                                                ServerConf->directory.alert))
                        {
                            hi_eo_client_event_log(Session,
                                                   HI_EO_CLIENT_SELF_DIR_TRAV,
                                                   NULL, NULL);
                        }

                        continue;
                    }
                }
  
                /*
                **  This means that we saw '.' and then another char, so
                **  it was just a file/dir that started with a '.'.
                */
                *ptr = orig_ptr;
                return iChar;
            }
        }

        /*
        **  This is where we write the chars after the slash
        */
        return iChar;
    }

    return END_OF_BUFFER;
}

/*
**  NAME
**    CheckLongDir::
*/
/**
**  This function checks for long directory names in the request URI.
**  
**  @param Session    pointer to the session
**  @param norm_state pointer to the directory stack
**  @param ub_ptr     current pointer in normalization buffer
**  
**  @return integer
**  
**  @retval HI_SUCCESS
*/
static int CheckLongDir(HI_SESSION *Session, URI_NORM_STATE *norm_state, 
                        u_char *ub_ptr)
{
    int    iDirLen;
    u_char *LastDir;

    /*
    **  First check that we are alerting on long directories and then
    **  check that we've seen a previous directory.
    */
    if(Session->server_conf->long_dir && norm_state->dir_count &&
       !norm_state->param)
    {
        LastDir = norm_state->dir_track[norm_state->dir_count - 1];

        iDirLen = ub_ptr - LastDir;

        if(iDirLen > Session->server_conf->long_dir &&
           hi_eo_generate_event(Session, HI_EO_CLIENT_OVERSIZE_DIR))
        {
            hi_eo_client_event_log(Session, HI_EO_CLIENT_OVERSIZE_DIR,
                                   NULL, NULL);
        }
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    InspectUriChar::
*/
/**
**  This function inspects the normalized chars for any other processing
**  that we need to do, such as directory traversals.
**  
**  The main things that we check for here are '/' and '?'.  There reason
**  for '/' is that we do directory traversals.  If it's a slash, we call
**  the routine that will normalize mutli-slashes, self-referential dirs,
**  and dir traversals.  We do all that processing here and call the
**  appropriate functions.
**  
**  The '?' is so we can mark the parameter field, and check for oversize
**  directories one last time.  Once the parameter field is set, we don't
**  do any more oversize directory checks since we aren't in the url
**  any more.
**  
**  @param Session      pointer to the current session
**  @param iChar        the char to inspect
**  @param norm_state   the normalization state
**  @param start        the start of the URI buffer
**  @param end          the end of the URI buffer
**  @param ptr          the address of the pointer index into the URI buffer
**  @param ub_start     the start of the norm buffer
**  @param ub_end       the end of the norm buffer
**  @param ub_ptr       the address of the pointer index into the norm buffer
**  
**  @return integer
**  
**  @retval END_OF_BUFFER    we've reached the end of the URI or norm buffer
**  @retval HI_NONFATAL_ERR  no special char, so just write the char and
**                           increment the ub_ptr.
**  @retval HI_SUCCESS       normalized the special char and already
**                           incremented the buffers.
*/
static INLINE int InspectUriChar(HI_SESSION *Session, int iChar,
                                 URI_NORM_STATE *norm_state,
                                 u_char *start, u_char *end, u_char **ptr,
                                 u_char *ub_start, u_char *ub_end,
                                 u_char **ub_ptr)
{
    HTTPINSPECT_CONF *ServerConf = Session->server_conf;
    int iDir;

    /*
    **  Let's add absolute URI/proxy support everyone.
    */
    if(!norm_state->dir_count && (u_char)iChar == ':' &&
       hi_util_in_bounds(start, end, ((*ptr)+2)))
    {
        if(**ptr == '/' && *((*ptr)+1) == '/')
        {
            /*
            **  We've found absolute vodka.
            */
            if(!hi_util_in_bounds(ub_start, ub_end, ((*ub_ptr)+2)))
                return END_OF_BUFFER;

            /*
            **  Write the :
            */
            **ub_ptr = (u_char)iChar;
            (*ub_ptr)++;

            /*
            **  This increments us past the first slash, so at the next
            **  slash we will track a directory.
            **
            **  The reason we do this is so that an attacker can't trick
            **  us into normalizing a directory away that ended in a :.
            **  For instance, if we got a URL that was separated in by a
            **  packet boundary like this, and we were looking for the
            **  URL real_dir:/file.html:
            **    real_dir://obfuscate_dir/../file.html
            **  we would normalize it with proxy support to:
            **    /file.html
            **  because we never tracked the :// as a valid directory.  So
            **  even though this isn't the best solution, it is the best
            **  we can do given that we are working with stateless
            **  inspection.
            */
            (*ptr)++;

            return HI_SUCCESS;
        }
    }

    /*
    **  Now that we have the "true" byte, we check this byte for other
    **  types of normalization:
    **    -  directory traversals
    **    -  multiple slashes
    */
    if((u_char)iChar == '/')
    {
        /*
        **  First thing we do is check for a long directory.
        */
        CheckLongDir(Session, norm_state, *ub_ptr);

        iDir = DirNorm(Session, start, end, ptr, norm_state);

        if(iDir == DIR_TRAV)
        {
            /*
            **  This is the case where we have a directory traversal.
            **
            **  The DirTrav function will reset the ub_ptr to the previous
            **  slash.  After that, we just continue through the loop because
            **  DirNorm has already set ptr to the slash, so we can just
            **  continue on.
            */
            DirTrav(norm_state, ub_start, ub_ptr);
        }
        else
        {
            /*
            **  This is the case where we didn't have a directory traversal,
            **  and we are now just writing the char after the '/'.
            **
            **  We call DirSet, because all this function does is write a
            **  '/' into the buffer and increment the ub_ptr.  We then
            **  check the return code and return END_OF_BUFFER if
            **  needed.
            */
            DirSet(norm_state, ub_ptr);
            if(iDir == END_OF_BUFFER)
                return END_OF_BUFFER;

            /*
            **  We check the bounds before we write the next byte
            */
            if(!hi_util_in_bounds(ub_start, ub_end, *ub_ptr))
                return END_OF_BUFFER;
            
            /*
            **  Set the char to what we got in DirNorm()
            */
            /*
            **  Look for user-defined Non-Rfc chars.  If we find them
            **  then log an alert.
            */
            if(ServerConf->non_rfc_chars[(u_char)iDir])
            {
                if(hi_eo_generate_event(Session, HI_EO_CLIENT_NON_RFC_CHAR))
                    hi_eo_client_event_log(Session, HI_EO_CLIENT_NON_RFC_CHAR,
                                           NULL, NULL);
            }

            **ub_ptr = (u_char)iDir;
            (*ub_ptr)++;
        }

        return HI_SUCCESS;
    }

    if((u_char)iChar == '?')
    {
        /*
        **  We assume that this is the beginning of the parameter field, 
        **  and check for a long directory following.  Event though seeing
        **  a question mark does not guarantee the parameter field, thanks
        **  IIS.
        */
        CheckLongDir(Session, norm_state, *ub_ptr);
        norm_state->param = *ub_ptr;
    }

    /*
    **  This is neither char, so we just bail and let the loop finish
    **  for us.
    */
    return HI_NONFATAL_ERR;
}

/*
**  NAME
**    hi_norm_uri::
*/
/**
**  Normalize the URI into the URI normalize buffer.
**  
**  This is the routine that users call to normalize the URI.  It iterates
**  through the URI buffer decoding the next character and is then checked
**  for any directory problems before writing the decoded character into the
**  normalizing buffer.
**  
**  We return the length of the normalized URI buffer in the variable,
**  uribuf_size.  This value is passed in as the max size of the normalization
**  buffer, which we then set in iMaxUriBufSize for later reference.
**  
**  If there was some sort of problem during normalizing we set the normalized
**  URI buffer size to 0 and return HI_NONFATAL_ERR.
**  
**  @param ServerConf   the pointer to the server configuration
**  @param uribuf       the pointer to the normalize uri buffer
**  @param uribuf_size  the size of the normalize buffer
**  @param uri          the pointer to the unnormalized uri buffer
**  @param uri_size     the size of the unnormalized uri buffer
**  
**  @return integer
**  
**  @retval HI_NONFATAL_ERR there was a problem during normalizing, the
**                          uribuf_size is also set to 0
**  @retval HI_SUCCESS      Normalizing the URI was successful
*/
int hi_norm_uri(HI_SESSION *Session, u_char *uribuf, int *uribuf_size,
                u_char *uri, int uri_size)
{
    HTTPINSPECT_CONF *ServerConf;
    int iChar;
    int iRet;
    int iMaxUriBufSize;
    URI_NORM_STATE norm_state;
    u_char *ub_ptr;
    u_char *ptr;
    u_char *start;
    u_char *end;
    u_char *ub_start;
    u_char *ub_end;

    ServerConf = Session->server_conf;

    iMaxUriBufSize = *uribuf_size;

    start = uri;
    end   = uri + uri_size;
    ub_start = uribuf;
    ub_end   = uribuf + iMaxUriBufSize;

    ub_ptr = uribuf;
    ptr    = uri;

    /*
    **  Initialize the URI directory normalization state
    */
    norm_state.dir_count = 0;
    norm_state.param     = NULL;

    while(hi_util_in_bounds(ub_start, ub_end, ub_ptr))
    {

        iChar = GetDecodedByte(Session, start, end, &ptr, &norm_state);
        if(iChar == END_OF_BUFFER)
            break;

        /*
        **  Look for user-defined Non-Rfc chars.  If we find them
        **  then log an alert.
        */
        if(ServerConf->non_rfc_chars[(u_char)iChar])
        {
            if(hi_eo_generate_event(Session, HI_EO_CLIENT_NON_RFC_CHAR))
                hi_eo_client_event_log(Session, HI_EO_CLIENT_NON_RFC_CHAR,
                                       NULL, NULL);
        }

        if((iRet=InspectUriChar(Session, iChar, &norm_state, start, end, &ptr,
                           ub_start, ub_end, &ub_ptr)))
        {
            if(iRet == END_OF_BUFFER)
                break;

            /*
            **  This is the default case when we don't want anything to do with
            **  the char besides writing the value into the buffer.
            */
            *ub_ptr = (u_char)iChar;
            ub_ptr++;
        }
    }

    /*
    **  Now that we are done, let's make sure that we didn't just have a
    **  single large directory, with the rest in the next packet.
    */
    CheckLongDir(Session, &norm_state, ub_ptr);

    /*
    **  This means that we got to the end of the URI, so we set the length,
    **  check it, and move on.
    */
    *uribuf_size = ub_ptr - ub_start;

    if(*uribuf_size > uri_size || *uribuf_size < 1)
        return HI_NONFATAL_ERR;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_norm_init::
*/
/**
**  Initialize the arrays neccessary to normalize the HTTP protocol fields.
**  
**  Currently, we set a hex_lookup array where we can convert the hex encoding
**  that we encounter in the URI into numbers we deal with.
**  
**  @param GlobalConf  pointer to the global configuration of HttpInspect
**  
**  @return HI_SUCCESS  function successful
*/
int hi_norm_init(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    int iCtr;
    int iNum;

    memset(hex_lookup, NO_HEX_VAL, sizeof(hex_lookup));
    memset(valid_lookup, NO_HEX_VAL, sizeof(valid_lookup));

    /*
    **  Set the decimal number values
    */
    iNum = 0;
    for(iCtr = 48; iCtr < 58; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    /*
    **  Set the upper case values.
    */
    iNum = 10;
    for(iCtr = 65; iCtr < 71; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    iNum = 16;
    for(iCtr = 71; iCtr < 91; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = BASE36_VAL;
        iNum++;
    }

    /*
    **  Set the lower case values.
    */
    iNum = 10;
    for(iCtr = 97; iCtr < 103; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = HEX_VAL;
        iNum++;
    }

    iNum = 16;
    for(iCtr = 103; iCtr < 123; iCtr++)
    {
        hex_lookup[iCtr] = iNum;
        valid_lookup[iCtr] = BASE36_VAL;
        iNum++;
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_normalization::
*/
/**
**  Wrap the logic for normalizing different inspection modes.
**  
**  We call the various normalization modes here, and adjust the appropriate
**  Session constructs.
**  
**  @param Session      pointer to the session structure.
**  @param iInspectMode the type of inspection/normalization to do
**  
**  @return integer
**  
**  @retval HI_SUCCESS      function successful
**  @retval HI_INVALID_ARG  invalid argument
*/
int hi_normalization(HI_SESSION *Session, int iInspectMode)
{
    int iRet;

    if(!Session)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Depending on the mode, we normalize the packet differently.
    **  Currently, we only have normalization routines for the client
    **  URI, so that's all we are interested in.
    **
    **  HI_SI_CLIENT_MODE:
    **    Inspect for HTTP client communication.
    */
    if(iInspectMode == HI_SI_CLIENT_MODE)
    {
        if((iRet = hi_client_norm((void *)Session)))
        {
            return iRet;
        }
    }

    return HI_SUCCESS;
}
