
/*
 * Argus Client Software.  Tools to read, analyze and manage Argus data.
 * Copyright (C) 2000-2004 QoSient, LLC.
 * All Rights Reserved
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 */

/*
 * template - argus client template.
 *
 *  This module must define these routines:
 *
 *   (void) usage (void);
 *                    this routine should print the standard usage message
 *                    for the specific application.
 *
 *          ArgusClientInit ();
 *                    this is the application specific init
 *                    routine, which is called after all parsing
 *                    initialization is done, prior to reading the
 *                    first argus(1) datum.
 *
 *   (void) ArgusClientTimeout ();
 *                    this routine is called every second, when
 *                    the argus client is connected to a remote
 *                    data source using the -S flag.
 *
 *          RaProcessRecord ((struct ArgusRecord *) argus);
 *                    this routine is called from the main library
 *                    for all Argus Records read from the stream.
 *                    The template suggests calling protocol specific
 *                    subroutines, but this is just a suggestion.
 *
 *   (void) RaArgusInputStart (struct ARGUS_INPUT *);
 *                    this routine will be called before each data
 *                    input source is processed.  Allows for per file.
 *                    initialization.
 *
 *   (void) RaArgusInputComplete (struct ARGUS_INPUT *);
 *                    this routine will be called after each data
 *                    input source is done.
 *
 *   (void) RaParseComplete (int);
 *                    this routine will be called after all the
 *                    monitor data has been read.
 *
 *
 *  These modules can optionally extend the common routines functions:
 *
 *          parse_arg (argc, argv)
 *                    this routine can process client specific command
 *                    line options, specified with appOptstring.
 *
 *
 *
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>


int RaInitialized = 0;
extern void ParseRulesFile(char *, int);
extern int fpCreateFastPacketDetection();

void
ArgusClientInit ()
{
   if (!(RaInitialized)) {
      RaInitialized++;

      if (ArgusFlowModelFile) {
         RaSnortInit(ArgusFlowModelFile);
         ParseRulesFile(ArgusFlowModelFile, 0);
         OtnXMatchDataInitialize();
         fpCreateFastPacketDetection();
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusClientInit: returning\n");
#endif
}

void RaArgusInputStart (struct ARGUS_INPUT *input) {};
void RaArgusInputComplete (struct ARGUS_INPUT *input) {};

int RaParseCompleting = 0;

void
RaParseComplete (int sig)
{
   if ((sig >= 0) && (!RaParseCompleting)) {
      RaParseCompleting++;

      if ((ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusWfileList)))) {
         struct ArgusWfileStruct *wfile = NULL, *start = NULL;
                     
         if ((wfile = ArgusFrontList(ArgusWfileList)) != NULL) {
            start = wfile;
            fflush(wfile->fd);
            ArgusPopFrontList(ArgusWfileList);
            ArgusPushBackList(ArgusWfileList, wfile);
            wfile = ArgusFrontList(ArgusWfileList);
         } while (wfile != start);
      }
   }

   fflush(stdout);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseComplete: returning\n");
#endif
}

void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusClientTimeout: returning\n");
#endif
}

void
parse_arg (int argc, char**argv)
{ 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "parse_arg: returning\n");
#endif
}


void
usage ()
{
   extern char version[];
   fprintf (stderr, "Ratemplate Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusProgramName);

   fprintf (stderr, "options: -a                print record summaries on termination.\n");
   fprintf (stderr, "         -A                print application bytes.\n");
   fprintf (stderr, "         -b                dump packet-matching code.\n");
   fprintf (stderr, "         -C                treat the remote source as a Cisco Netflow source.\n");
   fprintf (stderr, "         -D <level>        specify debug level\n");
   fprintf (stderr, "         -E <file>         write records that are rejected by the filter into <file>\n");
   fprintf (stderr, "         -f <flowfile>     read flow model from <flowfile>.\n");
   fprintf (stderr, "         -F <conffile>     read configuration from <conffile>.\n");
   fprintf (stderr, "         -h                print help.\n");
   fprintf (stderr, "         -n                don't convert numbers to names.\n");
   fprintf (stderr, "         -p <digits>       print fractional time with <digits> precision.\n");
   fprintf (stderr, "         -q                quiet mode. don't print record outputs.\n");
   fprintf (stderr, "         -r <file>         read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "         -R                print out response data when availabile.\n");
   fprintf (stderr, "         -S <host[:port]>  specify remote argus <host> and optional port number.\n");
   fprintf (stderr, "         -t <timerange>    specify <timerange> for reading records.\n");
   fprintf (stderr, "                  format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                           timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                               mm/dd[/yy]\n");
   fprintf (stderr, "                                               -%%d{yMhdms}\n");
   fprintf (stderr, "         -T <secs>         attach to remote server for T seconds.\n");
   fprintf (stderr, "         -u                print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>    specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "         -w <file>         write output to <file>. '-' denotes stdout.\n");
   fprintf (stderr, "         -z                print Argus TCP state changes.\n");
   fprintf (stderr, "         -Z <s|d|b>        print actual TCP flag values.<'s'rc | 'd'st | 'b'oth>\n");
   exit(1);
}


int RaLabelCounter = 0;
int RaSnortRetnValue = 0;

void
RaProcessRecord (struct ArgusRecord *argus)
{
   if (argus->ahdr.type & ARGUS_MAR)
      RaProcessManRecord (argus);

   else {
      switch (argus->ahdr.status & 0xFFFF) {
         case ETHERTYPE_IP:
            switch (argus->argus_far.flow.ip_flow.ip_p) {
               case IPPROTO_TCP:
                  RaProcessTCPRecord (argus);
                  break;

               case IPPROTO_UDP:
                  RaProcessUDPRecord (argus);
                  break;

               case IPPROTO_ICMP:
                  RaProcessICMPRecord (argus);
                  break;

               default:
                  RaProcessIPRecord (argus);
                  break;
            }
            break;

         case ETHERTYPE_ARP:
         case ETHERTYPE_REVARP:
            RaProcessARPRecord (argus);
            break;

         default:
            RaProcessNonIPRecord (argus);
            break;
      }
   }

   if (!qflag) {
      if (Lflag) {
         if (RaLabel == NULL)
            RaLabel = RaGenerateLabel(argus);

         if (!(RaLabelCounter++ % Lflag))
            printf ("%s\n", RaLabel);

         if (Lflag < 0)
            Lflag = 0;
      }

      printf ("%s\t: retn %d", get_argus_string (argus), RaSnortRetnValue);
      printf ("\n");
      fflush(stdout);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}


void
RaProcessManRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessManRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessTCPRecord (struct ArgusRecord *argus)
{
   RaSnortRetnValue = RaSnortProcessTCPRecord(argus);
#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessTCPRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessICMPRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessICMPRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessUDPRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessUDPRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessIPRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessIPRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessARPRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessARPRecord (0x%x) returning\n", argus);
#endif
}

void
RaProcessNonIPRecord (struct ArgusRecord *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessNonIPRecord (0x%x) returning\n", argus);
#endif
}

int RaSendArgusRecord(struct ArgusRecordStore *argus)
{
   int retn = 1;
#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord (0x%x) returning\n", argus);
#endif
   return (retn);
}

void ArgusWindowClose(void) 
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n");
#endif
}
