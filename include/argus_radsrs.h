/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2026 QoSient, LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

#ifndef ARGUS_RADSRS_H
#define ARGUS_RADSRS_H

#include <stddef.h>
#include <stdio.h>

struct ArgusRecordStruct;

/*
 * Render one RFC 7464 JSON text-sequence value.  The serialized buffer starts
 * with RS (0x1e), ends with a newline, and is owned by the caller on success.
 */
int ArgusRadsrsWriteRecord(FILE *out, const struct ArgusRecordStruct *record,
                           unsigned long sequence);
int ArgusRadsrsSerializeRecord(const struct ArgusRecordStruct *record,
                               unsigned long sequence, char **jsonseq,
                               size_t *jsonseq_len);
void ArgusRadsrsFreeSerializedRecord(char *jsonseq);

/*
 * This view is borrowed from the input buffer and is valid only during the
 * synchronous record callback.  Copy it before retaining it.
 */
int ArgusRadsrsGetRawRecord(const struct ArgusRecordStruct *record,
                            const unsigned char **raw, size_t *raw_length);
const char *ArgusRadsrsRecordFidelity(const struct ArgusRecordStruct *record,
                                      const unsigned char *raw,
                                      size_t raw_length);

#endif
