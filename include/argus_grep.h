/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_grep.h#5 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */


#ifndef ArgusGrep_h
#define ArgusGrep_h

#if defined(ARGUS_PCRE)
#include <pcreposix.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern void ArgusInitializeGrep (struct ArgusParserStruct *parser);
extern int ArgusGrepUserData (struct ArgusParserStruct *, struct ArgusRecordStruct *);

#ifdef __cplusplus
}
#endif

#endif  /* ArgusGrep_h */

