/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2026 QoSient, LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

/* radsrs command-line adapter for the shared JSON serializer. */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_radsrs.h>

extern struct ArgusParserStruct *ArgusParser;

static unsigned long RadsrsRecordCount;
static int RadsrsOutputFailed;

static void
RadsrsReportOutputFailure(struct ArgusParserStruct *parser)
{
   int saved_errno = errno;

   if (!RadsrsOutputFailed) {
      fprintf(stderr, "radsrs: unable to write JSON sequence: %s\n",
              strerror(saved_errno));
      RadsrsOutputFailed = 1;
   }
   if (parser != NULL) {
      parser->ArgusExitStatus = 1;
      parser->RaParseDone = 1;
   }
}

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   if (parser == NULL)
      return;

   parser->RaWriteOut = 0;
   if (parser->RaInitialized)
      return;

   (void)signal(SIGHUP, (void (*)(int))RaParseComplete);
   (void)signal(SIGTERM, (void (*)(int))RaParseComplete);
   (void)signal(SIGQUIT, (void (*)(int))RaParseComplete);
   (void)signal(SIGINT, (void (*)(int))RaParseComplete);
   parser->RaInitialized++;
}

void
RaArgusInputComplete(struct ArgusInput *input)
{
   (void)input;
}

void
RaParseComplete(int sig)
{
   if ((sig >= 0) && (ArgusParser != NULL) && !ArgusParser->RaParseCompleting++) {
      fflush(stdout);
      ArgusShutDown(sig);
   }

   switch (sig) {
      case SIGHUP:
      case SIGINT:
      case SIGTERM:
      case SIGQUIT:
         exit(0);
   }
}

void
ArgusClientTimeout(void)
{
   if (fflush(stdout) == EOF)
      RadsrsReportOutputFailure(ArgusParser);
}

void
parse_arg(int argc, char **argv)
{
   (void)argc;
   (void)argv;
}

void
usage(void)
{
   extern char version[];

   fprintf(stdout, "Radsrs Version %s\n", version);
   fprintf(stdout, "usage: %s [ra-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf(stdout, "\n");
   fprintf(stdout, "radsrs emits one pretty JSON text-sequence record for every matching Argus record.\n");
   fprintf(stdout, "Native V3/V5 input is preserved as Base64 wire bytes and accompanied by\n");
   fprintf(stdout, "a decoded view matching the structures in argus_out.h.\n");
   fprintf(stdout, "\n");
   fprintf(stdout, "Common input options:\n");
   fprintf(stdout, "  -r <file>          read an Argus data file; '-' reads standard input\n");
   fprintf(stdout, "  -S <host[:port]>   read a native Argus stream\n");
   fprintf(stdout, "  -F <file>          read a client configuration file\n");
   fprintf(stdout, "  -X                 do not read the default rarc file\n");
   fprintf(stdout, "  -t <range>         restrict records to a time range\n");
   fprintf(stdout, "  -h                 print this help\n");
   exit(1);
}

void
RaProcessRecord(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if ((parser == NULL) || (argus == NULL) || RadsrsOutputFailed)
      return;
   if ((ArgusRadsrsWriteRecord(stdout, argus, RadsrsRecordCount) < 0) ||
       (fflush(stdout) == EOF)) {
      RadsrsReportOutputFailure(parser);
      return;
   }
   RadsrsRecordCount++;
}

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   (void)argus;
   return 0;
}

void
ArgusWindowClose(void)
{
}
