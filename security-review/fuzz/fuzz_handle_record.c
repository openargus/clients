/*
 * Fuzz harness for the Argus client library's top-level record-ingestion entry point.
 *
 * Target: ArgusHandleRecord(struct ArgusParserStruct *, struct ArgusInput *,
 *                            struct ArgusRecord *, unsigned long, struct nff_program *)
 *         (common/argus_util.c:3650)
 *
 * This is the function called immediately after enough bytes for one Argus record have been
 * assembled from a stream/file (see e.g. common/argus_client.c's ArgusReadStreamSocket() and
 * common/argus_main.c's file-reading loop, both of which call
 * "ArgusHandleRecord (parser, input, rec, ...)" directly on a raw, still-network-byte-order
 * struct ArgusRecord buffer). Feeding it a raw record buffer exercises the whole downstream
 * parsing/canonicalization tree reachable from ArgusGenerateRecordStruct() -- every DSR type
 * (flow, metric, time, agr, mac, vlan, mpls, jitter, label, geo, etc.) -- without needing a
 * live network connection, a real input file, or root privileges.
 *
 * This harness replicates the minimal startup sequence performed by every ra* client's
 * main() (common/argus_main.c: ArgusNewParser -> ArgusMainInit -> ArgusClientInit), skipping
 * everything CLI/config/output/privilege-related that isn't needed to reach the parser code.
 *
 * Build: see security-review/fuzz/build.sh
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define ArgusMain

#include <argus_compat.h>
#include <argus_def.h>
#include <argus_out.h>
#include <signal.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Every ra* client (ra.c, racount.c, etc.) supplies these application-specific callbacks;
 * common/argus_main.c's main() and common/argus_util.c call them directly. This harness
 * doesn't link any client's .c file (they pull in printing/output code we don't need), so
 * provide minimal, faithful stand-ins. */

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 0;
   if (!(parser->RaInitialized)) {
      parser->RaInitialized++;
   }
}

void
RaArgusInputComplete(struct ArgusInput *input)
{
   (void) input;
}

void
ArgusClientTimeout(void)
{
}

void
RaParseComplete(int sig)
{
   (void) sig;
}

void
usage(void)
{
}

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   (void) argus;
   return 0;
}

void
ArgusWindowClose(void)
{
}

/* RaProcessRecord() is the final callback invoked (via RaScheduleRecord()) once a record has
 * passed filtering -- this is where each client does its actual application-level work
 * (printing, clustering, counting, etc.). For fuzzing the parsing path itself, a no-op is
 * sufficient and matches how e.g. racount.c's simplest modes behave when a record carries no
 * actionable data. */
void
RaProcessRecord(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   (void) parser;
   (void) argus;
}

/* Defined by common/argus_parser.c, which every ra* client links against. */
extern struct ArgusParserStruct *ArgusParser;

static struct ArgusInput *g_input;

static void
argus_harness_init(void)
{
   if ((ArgusParser = ArgusNewParser("fuzz_handle_record")) == NULL) {
      fprintf(stderr, "harness: ArgusNewParser failed\n");
      exit(1);
   }

   /* Skip ArgusMainInit()/ArgusParseArgs() entirely -- those parse argv/resource files and
    * pull in the full CLI surface. Set only what ArgusHandleRecord()'s call graph actually
    * dereferences unconditionally, matching the defaults ArgusNewParser() itself documents
    * (see common/argus_parser.c: nflag=1, Oflag=1, ArgusReverse=1, etc. already set there). */
   ArgusParser->RaCumulativeMerge = 1;

   /* An empty filter string compiles to "match everything" (common/argus_code.c:
    * ArgusFilterCompile() falls back to Argusgen_retblk() when root == NULL after parsing an
    * empty expression) -- this is exactly what every ra* client does by default when no -f/-F
    * filter is given on the command line. */
   if (ArgusFilterCompile(&ArgusParser->ArgusFilterCode, "", ArgusParser->Oflag) < 0) {
      fprintf(stderr, "harness: ArgusFilterCompile failed\n");
      exit(1);
   }

   ArgusClientInit(ArgusParser);

   /* ArgusHandleRecord()'s 2nd argument, "struct ArgusInput *input", is dereferenced for its
    * ArgusOriginal/ArgusOriginalBuffer scratch space and (for MAR records) input->srcid --
    * common/argus_util.c's ArgusInputFromFile() shows the expected initialization pattern. */
   if ((g_input = (struct ArgusInput *) calloc(1, sizeof(*g_input))) == NULL) {
      fprintf(stderr, "harness: calloc ArgusInput failed\n");
      exit(1);
   }
   g_input->fd = -1;
   g_input->ArgusOriginal = (struct ArgusRecord *) &g_input->ArgusOriginalBuffer;
   g_input->type = ARGUS_DATA_SOURCE;
}

/* One fuzzed iteration: feed `data` (of length `len`) to ArgusHandleRecord() as a raw,
 * network-byte-order Argus record buffer, exactly as the real stream/file readers do. */
static void
argus_harness_run_one(const unsigned char *data, size_t len)
{
   unsigned char buf[MAXARGUSRECORD];

   /* ArgusHandleRecord() trusts ptr->hdr.len (a 16-bit, network-byte-order word count) to
    * bound how much of the buffer it reads -- but only after first checking
    * "len < sizeof(input->ArgusOriginalBuffer)" against the *computed* len, not against how
    * many bytes we actually have. Real callers (ArgusReadStreamSocket) never invoke this
    * function unless input->ArgusReadSocketCnt >= length; replicate that same precondition
    * here so this harness matches the real call discipline exactly, rather than inventing an
    * out-of-contract call pattern that would just report "bugs" that can never be reached in
    * practice. */
   if (len < sizeof(struct ArgusRecordHeader) || len > sizeof(buf))
      return;

   memcpy(buf, data, len);

   {
      struct ArgusRecordHeader *hdr = (struct ArgusRecordHeader *) buf;
      unsigned long declared = ((unsigned long) ntohs(hdr->len)) * 4;

      if (declared == 0 || declared > len)
         return;
   }

   (void) ArgusHandleRecord(ArgusParser, g_input, (struct ArgusRecord *) buf, 0,
                             &ArgusParser->ArgusFilterCode);
}

int
main(int argc, char **argv)
{
   unsigned char filebuf[MAXARGUSRECORD];
   size_t n;
   int reps = 1;
   const char *r = getenv("REPLAY_REPS");

   if (r != NULL) reps = atoi(r);
   if (reps < 1) reps = 1;

   argus_harness_init();

   if (argc > 1) {
      for (int rep = 0; rep < reps; rep++) {
         for (int a = 1; a < argc; a++) {
            FILE *fp = fopen(argv[a], "rb");
            if (fp == NULL) {
               fprintf(stderr, "harness: cannot open %s: %s\n", argv[a], strerror(errno));
               continue;
            }
            n = fread(filebuf, 1, sizeof(filebuf), fp);
            fclose(fp);
            argus_harness_run_one(filebuf, n);
         }
      }
   } else {
      n = fread(filebuf, 1, sizeof(filebuf), stdin);
      argus_harness_run_one(filebuf, n);
   }

   return 0;
}
