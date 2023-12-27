/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2014 QoSient, LLC
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
 */

/*
 * Race Client Software.  Tools to read, analyze and manage Race data.
 * Copyright (C) 2000-2014 QoSient, LLC.
 * All Rights Reserved
 *
 * raced - this is the RACE daemon.
 *    This program manages the tasks required to support a RACE information system node.
 *    The principal functions are to maintain the RACE database, and to
 *    start and stop tasks on behalf of the raced.  These tasks do the
 *    specific functions of the raced, such as connecting to the global
 *    event distribution system, etc.....
 *
 *    As a part of the RACE database maintenace responsibilities, the
 *    raced will repair any RACE system tables, and attempt to keep the
 *    RACE data current.
 *
 *    The raced will also start and maintain the collection of local
 *    raced tasks.  Of particular importance is the spawning and status reporting
 *    on the individual RACE user project tasks.  These include the project specific
 *    radii and stream block processors (SBP) that are used by any particular project.
 *
 *    The RACE node should be considered a member of a federated database, and the
 *    raced could provides all the tasks required to be a part of that federation.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/race/raced.c#6 $
 * $DateTime: 2016/09/13 10:40:12 $
 * $Change: 3180 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
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
#include <argus_grep.h>
#include <argus_dscodepoints.h>

#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#if defined(CYGWIN)
#include <getopt.h>
#endif

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdarg.h>
#include <ctype.h>

char *getoptStr = "dD:pP:u:U:F:f:M:";
char *RaceProgramArgs = NULL;
char *RaceHost = NULL;
char *RaceUser = NULL;
char *RacePass = NULL;
char *RaceDataBase = "race";

char *print_time(struct timeval *);

int RaceParseResourceFile (char *);
void usage(void);

void RaceHUPSignal (int);
void RaceShutDown (int);

int RaceShutDownFlag = 0;

extern char *RaHomePath;

#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"
#endif


#define RA_MAXTABLES		6
#define RA_MAXTABLES_MASK	0x0003F
unsigned int RaceTableFlags = 0;

int RaceDataBaseExists = 0;

char *RaceExistsTableNames[RA_MAXTABLES];
char *RaceCreateTableNames[RA_MAXTABLES] = {
   "Accounts",
   "Probes",
   "Access",
   "Projects",
   "Messages",
   "Tasks",
};

/*
  The RACE Database holds account information and entries for entire
  sets of ra data.  These can be considered projects, and as such are
  complete databases, with data archives, data entry strategies,
  attributes and status.
 
  RACE.Accounts schema.
  
  +----------+------------------+------+-----+---------+----------------+
  | Field    | Type             | Null | Key | Default | Extra          |
  +----------+------------------+------+-----+---------+----------------+
  | uid      | int(11)          |      | PRI | NULL    | auto_increment |
  | name     | varchar(255)     |      |     |         |                |
  | fullname | varchar(255)     | YES  |     | NULL    |                |
  | address  | varchar(255)     | YES  |     | NULL    |                |
  | telephone| varchar(32)      | YES  |     | NULL    |                |
  | mobile   | varchar(32)      | YES  |     | NULL    |                |
  | fax      | varchar(32)      | YES  |     | NULL    |                |
  | email    | varchar(255)     | YES  |     | NULL    |                |
  | url      | varchar(255)     | YES  |     | NULL    |                |
  | password | varchar(255)     |      |     |         |                |
  | filter   | varchar(255)     | YES  |     | NULL    |                |
  | status   | varchar(8)       |      |     |         |                |
  +----------+------------------+------+-----+---------+----------------+


  RACE.Probes schema.

  +-------------+---------------+------+-----+---------+----------------+
  | Field       | Type          | Null | Key | Default | Extra          |
  +-------------+---------------+------+-----+---------+----------------+
  | id          | int(11)       |      | PRI | NULL    | auto_increment |
  | name        | varchar(32)   |      |     |         |                |
  | url         | varchar(255)  |      |     |         |                |
  | type        | varchar(255)  | YES  |     | NULL    |                |
  | filter      | varchar(255)  | YES  |     | NULL    |                |
  | authname    | varchar(255)  | YES  |     | NULL    |                |
  | authpass    | varchar(255)  | YES  |     | NULL    |                |
  | description | varchar(255)  | YES  |     | NULL    |                |
  | access      | timestamp(6) | YES  |     | NULL    |                |
  | created     | timestamp(6) | YES  |     | NULL    |                |
  +-------------+---------------+------+-----+---------+----------------+


  RACE.Access schema.
  
  +----------+------------------+------+-----+---------+----------------+
  | Field    | Type             | Null | Key | Default | Extra          |
  +----------+------------------+------+-----+---------+----------------+
  | user     | varchar(32)      |      |     |         |                |
  | rmtaddr  | varchar(16)      |      |     |         |                |
  | session  | varchar(255)     |      |     |         |                |
  | nonce    | varchar(255)     |      |     |         |                |
  | access   | timestamp        |      |     |         |                |
  | created  | timestamp        |      |     |         |                |
  +----------+------------------+------+-----+---------+----------------+


  The RACE Database holds entries for entire sets of ra data.  These
  can be considered projects, and as such are complete databases, with
  data archives, data entry strategies, attributes and status.

  RACE.Projects schema.
 
  +----------+------------------+------+-----+---------+----------------+
  | Field    | Type             | Null | Key | Default | Extra          |
  +----------+------------------+------+-----+---------+----------------+
  | id       | int(11)          |      | PRI | NULL    | auto_increment |
  | name     | varchar(255)     |      |     |         |                |
  | uid      | int(11)          |      |     | 0       |                |
  | source   | varchar(255)     | YES  |     | NULL    |                |
  | archive  | varchar(255)     | YES  |     | NULL    |                |
  | format   | varchar(255)     | YES  |     | NULL    |                |
  | period   | int(11)          | YES  |     | NULL    |                |
  | size     | bigint(10)       | YES  |     | NULL    |                |
  | pid      | int(10) unsigned | YES  |     | NULL    |                |
  | creation | int(10) unsigned | YES  |     | NULL    |                |
  | start    | int(10) unsigned | YES  |     | NULL    |                |
  | stop     | int(10) unsigned | YES  |     | NULL    |                |
  | map      | varchar(255)     | YES  |     | NULL    |                |
  | spacedef | varchar(255)     | YES  |     | NULL    |                |
  | status   | int(1)           | YES  |     | NULL    |                |
  +----------+------------------+------+-----+---------+----------------+


  The fields are:
     id       - the index number for the acutal Entry.
     name     - the displayable name for the project.
     source   - An intermediate data file that contains data
                relevant to the project.
     uid      - the user id from the accounts file.
     archive  - an archive repository directory.  A project doesn't
                have to have a repository, however if there is more
                than one data file, the collection of files is a
                repository of some kind.  while archives should have
                a formal structure, it is up to applications to determine
                what type of archive is referenced.
     format   - file name specification for the archive.  This is
                string that will be used by rasplit() style file
                creation, so that it can substitute the time and
                various record details into the resulting filename.
     period   - the polling interval for processing data from the source
                to the archive.  this helps applications to understand
                when to look in the archive and when to look in the source
                file.  A (period = 0) indicates never.
     pid      - the pid of any
     creation -
     start    -
     stop     -
     map      -
     spacedef -
     status   -
              

  RACE.Messages schema.

  +-----------+---------------+------+-----+---------------------+----------------+
  | Field     | Type          | Null | Key | Default             | Extra          |
  +-----------+---------------+------+-----+---------------------+----------------+
  | id        | int(11)       |      | PRI | NULL                | auto_increment |
  | ntaisid   | varchar(255)  |      |     |                     |                |
  | uid       | int(11)       |      |     | 0                   |                |
  | sender    | varchar(255)  |      |     |                     |                |
  | recipient | varchar(255)  |      |     |                     |                |
  | subject   | varchar(255)  | YES  |     | NULL                |                |
  | date      | datetime      |      |     | 0000-00-00 00:00:00 |                |
  | access    | timestamp(6) | YES  |     | NULL                |                |
  | message   | text          | YES  |     | NULL                |                |
  | status    | int(2)        | YES  |     | NULL                |                |
  | priority  | int(2)        | YES  |     | NULL                |                |
  | url       | varchar(255)  | YES  |     | NULL                |                |
  +-----------+---------------+------+-----+---------------------+----------------+

  RACE.Tasks schema.
 
  +---------+--------------+------+-----+---------------------+----------------+
  | Field   | Type         | Null | Key | Default             | Extra          |
  +---------+--------------+------+-----+---------------------+----------------+
  | id      | int(11)      |      | PRI | NULL                | auto_increment |
  | project | varchar(255) |      | PRI |                     |                |
  | task    | int(11)      |      |     | 0                   |                |
  | type    | varchar(255) |      |     |                     |                |
  | program | varchar(255) |      |     |                     |                |
  | params  | varchar(255) | YES  |     | NULL                |                |
  | dir     | varchar(255) | YES  |     | NULL                |                |
  | pid     | int(5)       | YES  |     | NULL                |                |
  | date    | datetime     |      |     | 0000-00-00 00:00:00 |                |
  | status  | int(2)       | YES  |     | NULL                |                |
  +---------+--------------+------+-----+---------------------+----------------+
*/

char *RaceTableCreationString[RA_MAXTABLES] = {
   "CREATE TABLE Accounts (uid int not null auto_increment, name varchar(32) not null, fullname varchar(255), address varchar(255), telephone varchar(32), mobile varchar(32), fax varchar(32), email varchar(255), url varchar(255), password varchar(32) not null, filter varchar(255), status varchar(8) not null, primary key (uid)) ENGINE=MYISAM",

   "CREATE TABLE Probes (id int not null auto_increment, name varchar(32) not null, url varchar(255) not null, type varchar(255), filter varchar(255), authname varchar(255), authpass varchar(255), description varchar(255), access timestamp(6), created timestamp(6), primary key (id)) ENGINE=MYISAM",

   "CREATE TABLE Access (name varchar(32) not null, rmtaddr varchar(16) not null, session varchar(255) not null, nonce varchar(255) not null, access timestamp(6), created timestamp(6)) ENGINE=MYISAM",

   "CREATE TABLE Projects (id int not null auto_increment, name varchar(255) not null, uid int(11) not null, source varchar(255), archive varchar(255), format varchar(255), period int, size bigint not null, pid int unsigned, creation int unsigned, start int unsigned, stop int unsigned, map varchar (255), spacedef varchar (255), status int (1), primary key (id)) ENGINE=MYISAM",

   "CREATE TABLE Messages (id int not null auto_increment, ntaisid varchar(255) not null, uid int(11) not null, sender varchar(255) not null, recipient varchar(255) not null, subject varchar(255), date datetime not null, access timestamp(6), message text, status int (2), priority int (2), url varchar(255), primary key (id)) ENGINE=MYISAM",

   "CREATE TABLE Tasks (id int not null auto_increment, project varchar(255) not null, task int(11) not null, type varchar(255) not null, program varchar(255) not null, params varchar(255), dir varchar(255), pid int(5), date datetime not null, status int(2), primary key (id,project)) ENGINE=MYISAM",
};

#define RaceEnvItems      2
 
char *RaceResourceEnvStr [] = {
   "HOME",
   "RACEHOME",
};
 
char *RaceHomePath = NULL;
char *RaceAccountName = NULL;
char *RaceAccountFilter = NULL;
int RaceNewAccount = 0;

char *MDString(char *);


struct RaceModeStruct {
   struct RaceModeStruct *nxt;
   char *mode;
}; 

#define ARGUS_SCRIPT_TIMEOUT            30

#define RACE_ECHILD_ALARM		1
 
struct RaceTaskStruct {
   struct timeval startime, stoptime; 
   int id, tasknum, status, alarm, timeout;
   char *type, *project, *program;
   char *params, *dir; 
   pid_t pid;  
};
 
struct RaceListObjectStruct {
   struct RaceListObjectStruct *nxt, *prv;
   void *obj;
}; 
 
struct RaceListStruct {
   struct RaceListObjectStruct *start;
   struct timeval outputTime, reportTime;
   unsigned int count;
}; 

struct RaceDaemonStruct {
   struct RaceDaemonStruct *prv, *nxt;
   int status, debug, debugflag, daemonflag;
   int RaceCheckConfFlag;
   struct RaceListStruct *tasks;
   struct RaceModeStruct *RaceModeList;
   pid_t RaceChildPid;
   pid_t RaceSessionId;
   char *RacePidFile;

   struct timeval start, last, now;
};

struct RaceDaemonStruct *RaceDaemon;

int RaceInit(struct RaceDaemonStruct *);
void RaceLoop(struct RaceDaemonStruct *);

int RaceAddModeList (struct RaceDaemonStruct *, char *);
void RaceDeleteModeList (struct RaceDaemonStruct *);

int RaceCheckDatabases(struct RaceDaemonStruct *);

struct RaceListStruct *RaceNewList (void);
void RaceDeleteList (struct RaceListStruct *);
int RaceListEmpty (struct RaceListStruct *);
int RaceGetListCount(struct RaceListStruct *);
void RacePushFrontList(struct RaceListStruct *, void *);
void RacePushBackList(struct RaceListStruct *, void *);
void *RaceFrontList(struct RaceListStruct *);
void *RaceBackList(struct RaceListStruct *);
void RacePopBackList(struct RaceListStruct *);
void RacePopFrontList(struct RaceListStruct *);
void RaceSortList(struct RaceListStruct *);
int RaceListCmp(struct RaceListStruct *, struct RaceListStruct *);
struct RaceListStruct *RaceGetChangeList(struct RaceListStruct *, struct RaceListStruct *);
struct RaceListStruct *RaceMergeList(struct RaceDaemonStruct *, struct RaceListStruct *, struct RaceListStruct *);

struct RaceListStruct *RaceGetTaskList(struct RaceDaemonStruct *);
int RaceProcessTaskList(struct RaceDaemonStruct *, struct RaceListStruct *);
void RaceDeleteTask(struct RaceDaemonStruct *,  struct RaceTaskStruct *);
void RaceDeleteTaskList (struct RaceDaemonStruct *,  struct RaceListStruct *);

struct RaceDaemonStruct *RaceNewDaemon (void);

#define RACED_START	0
#define RACED_PROCESS	1
#define RACED_STOP	2
                                                                                                                           

int ArgusStatus  = RACED_START;
int ArgusPassNum = 1;
int ArgusPortNum = 0;

void RaceHupSig (int);
void RaceUsr1Sig (int);
void RaceUsr2Sig (int);

#if defined(ARGUS_MYSQL)
MYSQL_RES *mysqlRes;
MYSQL_ROW row;
MYSQL mysql;
#endif

#define RAENVITEMS	2
int
main (int argc, char **argv)
{
   struct RaceDaemonStruct *raced = NULL;
   char userbuf[1024], *sptr = NULL, *hptr = NULL;
   char *cmdbuf = NULL, *str = NULL;
   int i, cc, op, retn = 0, status;
   char path[MAXPATHNAMELEN];
   char *envstr = NULL;
   struct stat statbuf;
   pid_t pid;

#if defined(ARGUS_THREADS)
   pthread_attr_t attr;
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   size_t stacksize;
#endif

   opterr = 0;

   (void) signal (SIGHUP,  (void (*)(int)) RaceHupSig);
   (void) signal (SIGTERM, (void (*)(int)) RaceShutDown);
   (void) signal (SIGQUIT, (void (*)(int)) RaceShutDown);
   (void) signal (SIGINT,  (void (*)(int)) RaceShutDown);
   (void) signal (SIGUSR1, (void (*)(int)) RaceUsr1Sig);
   (void) signal (SIGUSR2, (void (*)(int)) RaceUsr2Sig);

   if ((RaceDaemon = RaceNewDaemon()) == NULL)
      ArgusLog (LOG_ERR, "RaceNewDaemon() failed");
                                                                                                                           
   raced = RaceDaemon;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (cc > 0) {
      int len = cc + (argc + 1);

      if ((RaceProgramArgs = (char *) calloc (len, sizeof(char))) != NULL) {
         for (i = 0, *RaceProgramArgs = '\0'; i < argc; i++) {
            strcat (RaceProgramArgs, argv[i]);
            strcat (RaceProgramArgs, " ");
         }
      } else
         ArgusLog (LOG_ERR, "calloc(%d, %d) failed %s\n", len, sizeof(char), strerror(errno));
   }

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((ArgusParser = ArgusNewParser(argv[0])) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(&attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(&attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(&attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(&attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE     524288

   if (pthread_attr_getstacksize(&attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
#endif
      if (pthread_attr_setstacksize(&attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");
   }
#endif

   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
#endif

   snprintf (path, MAXPATHNAMELEN - 1, "/etc/race.conf");

   if (stat (path, &statbuf) == 0)
      RaceParseResourceFile (path);

   if ((envstr = getenv("ARGUSPATH")) != NULL) {
      while ((RaHomePath = strtok(envstr, ":")) != NULL) {
         snprintf (path, MAXPATHNAMELEN - 1, "%s/.rarc", RaHomePath);
         if (stat (path, &statbuf) == 0) {
            RaceParseResourceFile (path);
            break;
         }
         envstr = NULL;
      }

   } else {
      for (i = 0; i < RAENVITEMS; i++) {
         envstr = RaceResourceEnvStr[i];
         if ((RaHomePath = getenv(envstr)) != NULL) {
            sprintf (path, "%s/.rarc", RaHomePath);
            if (stat (path, &statbuf) == 0) {
               RaceParseResourceFile (path);
               break;
            }
         }
      }
   }

   while ((op = getopt (argc, argv, getoptStr)) != EOF) {
      switch (op) {
         case 'd': raced->daemonflag++; break;
         case 'D':
            raced->debugflag = atoi(optarg);
            ArgusParser->debugflag = atoi(optarg);
            break;
         case 'p':
            RacePass = getpass("Password: ");
            break;
         case 'u': 
            if (optarg != NULL) {
               strncpy (userbuf, optarg, sizeof(userbuf));
               if ((sptr = strchr (userbuf, '/')) != NULL)
                  *sptr = '\0';
               if ((hptr = strchr (userbuf, '@')) != NULL)
                  *hptr++ = '\0';
                                                                                                                      
               RaceUser = userbuf;
               RaceHost = hptr;
            }
            break;

         case 'F':
            if (!(RaceParseResourceFile (optarg)))
               ArgusLog(LOG_ERR, "%s: %s", optarg, strerror(errno));
            break;

         case 'M':
            do {
               if (!(RaceAddModeList (raced, optarg))) {
                  ArgusLog(LOG_ERR, "%s: error: file arg %s", *argv, optarg);
               }
               if ((optarg = argv[optind]) != NULL)
                  if (*optarg != '-')
                     optind++;
            } while (optarg && (*optarg != '-'));
            break;

         case 'h':
            default:  
               usage ();
            /* NOTREACHED */
      }
   }

   if ((str = argv[optind]) != NULL) {
      if (strcmp(str, "-") == 0)
         optind++;  
      cmdbuf = copy_argv (&argv[optind]);
   }

   if (raced->daemonflag) {
      if (chdir ("/") < 0) 
         ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

      if ((pid = fork ()) < 0) {
         ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
      } else {
         FILE *tmpfile = NULL;
         if (pid) {
            int status;

            usleep(200000);
            waitpid(pid, &status, WNOHANG);
            if (kill(pid, 0) < 0) {
               exit (1);
            } else
               exit (0);

         } else {
            if ((tmpfile = freopen ("/dev/null", "w", stdout)) == NULL)
               ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

            if ((tmpfile = freopen ("/dev/null", "w", stderr)) == NULL)
               ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
         }
      }
   }
 
   RaceAccountFilter = cmdbuf;
   bzero((char *)RaceExistsTableNames, sizeof(RaceExistsTableNames));

   if (ArgusParser->pidflag)
      ArgusCreatePIDFile (ArgusParser, ArgusParser->ArgusProgramName);
 
   while (!(RaceShutDownFlag)) {
      if (raced->daemonflag) {
         if (!(raced->RaceChildPid = fork())) {
            ArgusLog(LOG_ALERT, "started");
            if (RaceInit(raced)) 
               RaceLoop(raced);
            else
               RaceShutDownFlag = 1;
            ArgusLog(LOG_WARNING, "exiting");
    
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "parent waiting for child pid %d", raced->RaceChildPid);
#endif
            waitpid (raced->RaceChildPid, &status, 0);

            if (!(RaceShutDownFlag)) {
               char strbuf[1024];
               sprintf (strbuf, "daemon[%d] ", (int) raced->RaceChildPid);

               if (WIFEXITED(status)) {
                  sprintf (&strbuf[strlen(strbuf)], "exited with 0x%x ", WEXITSTATUS(status));
               }

               if (WIFSIGNALED(status)) {
                  sprintf (&strbuf[strlen(strbuf)], "terminated: signal(%d) ", WTERMSIG(status));
               }
#ifdef WCOREDUMP
               if (WCOREDUMP(status))
                  sprintf (&strbuf[strlen(strbuf)], "dumped core ");
#endif
            } else
               ArgusLog(LOG_ALERT, "shutdown");
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "started");
#endif
         if (RaceInit(raced))
            RaceLoop(raced);
         else
            RaceShutDownFlag = 1;
#ifdef ARGUSDEBUG
         ArgusDebug (1, "shutdown");
#endif
      }
   }

#if defined(ARGUS_MYSQL)
   mysql_close(&mysql);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "exiting retn %d", retn);
#endif
   exit (retn);
}


struct RaceDaemonStruct *
RaceNewDaemon ()
{
   struct RaceDaemonStruct *raced = NULL;

   if ((raced = (struct RaceDaemonStruct *) ArgusCalloc (1, sizeof (struct RaceDaemonStruct))) == NULL)
      ArgusLog(LOG_ERR, "RaceNewDaemon: ArgusCalloc error %s", strerror(errno));

   gettimeofday (&raced->start, 0L);
   gettimeofday (&raced->now, 0L);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceNewDaemon() returns 0x%x", raced);
#endif
   return (raced);
}


#define RACE_MAXMODES		1
#define RACEDEBUG		0

char *RaceDaemonModes[RACE_MAXMODES] = {
   "debug",
};


#define RACE_MAXDEBUG		2

#define RACE_DEBUGDUMMY	0
#define RACE_DEBUGTASKS	1

#define RACE_DEBUGTASKMASK	1

char *ArgusDebugModes[RACE_MAXDEBUG] = {
   " ",
   "tasks",
};


int
RaceInit(struct RaceDaemonStruct *raced)
{
   int retn = 0;
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceInit()");
#endif

   if (raced != NULL) {
      struct RaceModeStruct *mode = NULL;
      int i, x, ind;

#if defined(ARGUS_MYSQL)
      MYSQL *tsql = NULL;
      int tries;
#ifdef ARGUSDEBUG
      char sbuf[256];
#endif
#endif

      if ((mode = raced->RaceModeList) != NULL) {
         while (mode) {
            for (i = 0, ind = -1; i < RACE_MAXMODES; i++) {
               if (!(strncasecmp (mode->mode, RaceDaemonModes[i], 3))) {
                  ind = i;
                  switch (ind) {
                     case RACEDEBUG:
                        if ((mode = mode->nxt) == NULL)
                           usage();
                        break;
                  }
               }
            }
            if (ind < 0)
               usage();

            switch (ind) {
               case RACEDEBUG: {
                  for (x = 0, ind = -1; x < RACE_MAXMODES; x++) {
                     if (!(strncasecmp (mode->mode, RaceDaemonModes[x], 3))) {
                        raced->debug = x << ind;
                        switch (ind) {
                           case RACE_DEBUGTASKS:
                              break;
                        }
                     }
                  }
                  break;
               }

               default:
                  usage();
                  break;
            }

            mode = mode->nxt;
         }
      }

#if defined(ARGUS_MYSQL)
      if ((mysql_init(&mysql)) == NULL)
         ArgusLog(LOG_ERR, "mysql_init failed");

      mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

#ifdef ARGUSDEBUG
      sprintf (sbuf, "RaceCheckDatabases(0x%p) connecting to host ", raced);
      if (RaceHost)
         sprintf (&sbuf[strlen(sbuf)], "%s ", RaceHost);
      else
         sprintf (&sbuf[strlen(sbuf)], "localhost ");
                                                                                                                           
      if (RaceUser)
         sprintf (&sbuf[strlen(sbuf)], "as user %s ", RaceUser);
                                                                                                                           
      ArgusDebug (1, sbuf);
#endif
                                                                                                                           
      if (raced->daemonflag)
         tries = 30;
      else
         tries = 1;
                                                                                                                           
      while (tries-- > 0) {
         if ((tsql = mysql_real_connect(&mysql, RaceHost, RaceUser, RacePass, NULL, 0, NULL, 0)) != NULL)
            break;
         if (tries > 0)
            usleep (250000);
      }
                                                                                                                           
      if (tsql != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "mysql_real_connect() connected as %s.\n", RaceUser);
#endif

         RaceCheckDatabases(raced);
         raced->RaceCheckConfFlag++;
         retn = 1;
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_connect() error %s", mysql_error(&mysql));
#endif
      }
#endif
   }
   return (retn);
}



/*

describe Tasks;
+---------+--------------+------+-----+---------------------+----------------+
| Field   | Type         | Null | Key | Default             | Extra          |
+---------+--------------+------+-----+---------------------+----------------+
| id      | int(11)      |      | PRI | NULL                | auto_increment |
| project | varchar(255) |      | PRI |                     |                |
| task    | int(11)      |      |     | 0                   |                |
| type    | varchar(255) |      |     |                     |                |
| program | varchar(255) |      |     |                     |                |
| params  | varchar(255) | YES  |     | NULL                |                |
| dir     | varchar(255) | YES  |     | NULL                |                |
| pid     | int(5)       | YES  |     | NULL                |                |
| date    | datetime     |      |     | 0000-00-00 00:00:00 |                |
| status  | int(2)       | YES  |     | NULL                |                |
+---------+--------------+------+-----+---------------------+----------------+

  
struct RaceTaskStruct { 
   struct timeval startime;  
   char *project, *program, *params, *dir; 
   int id, tasknum, status, timeout;   
   pid_t pid;  
}; 

*/

void
RaceDeleteTask(struct RaceDaemonStruct *raced, struct RaceTaskStruct *task)
{
   if (task->project) {
      free(task->project);
      task->project = NULL;
   }
   if (task->program) {
      free(task->program);
      task->program = NULL;
   }
   if (task->params) {
      free(task->params);
      task->params = NULL;
   }
   if (task->type) {
      free(task->type);
      task->type = NULL;
   }
   if (task->dir) {
      free(task->dir);
      task->dir = NULL;
   }

   ArgusFree(task);
}


struct RaceListStruct *
RaceGetTaskList(struct RaceDaemonStruct *raced)
{
   struct RaceListStruct *list = NULL;
#if defined(ARGUS_MYSQL)
   struct RaceTaskStruct *task = NULL;
   char *project = "", *program = "", *params = "", *dir = "", *type = "";
   char sbuf[1024], *ptr;
   int retn = 0;

   bzero(sbuf, sizeof(sbuf)); 
   sprintf (sbuf, "SELECT id,project,task,type,program,params,dir,pid,status FROM Tasks");

 
   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));
   else {
      if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) == 9) {
            if ((list = RaceNewList()) == NULL) 
               ArgusLog(LOG_ERR, "RaceNewList failed");

            while ((row = mysql_fetch_row(mysqlRes)) != NULL) {
               int id = 0, tasknum = 0, status = 0, pid = 0;

               if (row[0]) {
                  id = strtol(row [0], (char **)&ptr, 10);
                  if (ptr == row[0])
                     ArgusLog(LOG_ERR, "status field format incorrect %s", row[0]);
               }
               if (row[1]) project   = row [1];
               if (row[2]) {
                  tasknum = strtol(row [2], (char **)&ptr, 10);
                  if (ptr == row[2])
                     ArgusLog(LOG_ERR, "status field format incorrect %s", row[2]);
               }
               if (row[3]) type      = row [3];
               if (row[4]) program   = row [4];
               if (row[5]) params    = row [5];
               if (row[6]) dir       = row [6];
               if (row[7]) {
                  pid = strtol(row [7], (char **)&ptr, 10);
                  if (ptr == row[7])
                     ArgusLog(LOG_ERR, "pid field format incorrect %s", row[7]);
               }

               if (row[8]) {
                  status    = strtol(row [8], (char **)&ptr, 10);
                  if (ptr == row[8])
                     ArgusLog(LOG_ERR, "status field format incorrect %s", row[8]);
               }

               if ((task = (struct RaceTaskStruct *) ArgusMalloc(sizeof(*task))) == NULL)
                  ArgusLog(LOG_ERR, "RaceGetTaskList malloc error %s", strerror(errno));

               task->id      = id;
               task->project = strdup(project);
               task->program = strdup(program);
               task->params  = strdup(params);
               task->type    = strdup(type);
               task->dir     = strdup(dir);
               task->tasknum = tasknum;
               task->pid     = pid;
               task->status  = status;

               RacePushBackList(list, task);

#ifdef ARGUSDEBUG
               ArgusDebug (3, "RaceGetTaskList cataloging task %s pid %d", task->program, task->pid);
#endif
            }

         } else 
            ArgusLog(LOG_ERR, "mysql query %s returned %d items", sbuf, retn);

         mysql_free_result(mysqlRes);
      }
   }
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaceGetTaskList returns 0x%x", list);
#endif

   return (list);
}


int
RaceProcessTaskList(struct RaceDaemonStruct *raced, struct RaceListStruct *list)
{
   int retn = 0, count, i, status;
   struct RaceTaskStruct *task = NULL;
   struct RaceListStruct *clist = NULL;

   if (raced->tasks && (!(RaceListEmpty(raced->tasks)))) {
      RaceSortList(list);

      if ((clist = RaceGetChangeList(raced->tasks, list)) != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "RaceGetChangeList: returned %d tasks to stop", clist->count);
#endif
         for (i = 0, count = clist->count; i < count; i++) {
            if ((task = (struct RaceTaskStruct *) RaceFrontList(clist)) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (3, "RaceProcessTaskList: stop task: project %s process %d", task->project, task->pid);
#endif
               if (kill (task->pid, SIGINT) == 0) {
                  waitpid (task->pid, &status, 0);
                  ArgusLog (LOG_ALERT, "RaceProcessTaskList: Killed task[%d]: project %s.%s task %d '%s'",
                     task->pid, task->project, task->type, task->tasknum, task->program);
               } else
                  ArgusLog(LOG_ALERT, "kill(%d, SIGINT)  failed %s", strerror(errno));
               
               RacePopFrontList(clist);
               RaceDeleteTask(raced, task);
            }
         }
         RaceDeleteList(clist);

         RaceMergeList(raced, raced->tasks, list);

         for (i = 0, count = raced->tasks->count; i < count; i++) {
            if ((task = (struct RaceTaskStruct *) RaceFrontList(raced->tasks)) != NULL) {
               
               RacePopFrontList(raced->tasks);
               RacePushBackList(raced->tasks, task);
            }
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "RaceProcessTaskList: no task configuration changes");
#endif
      }

   } else {

      if (raced->tasks == NULL)
         if ((raced->tasks = RaceNewList()) == NULL)
            ArgusLog(LOG_ERR, "RaceNewList failed");

      while ((task = (struct RaceTaskStruct *) RaceFrontList(list)) != NULL) {
         RacePopFrontList(list);
         RacePushBackList(raced->tasks, task);
      }

      RaceSortList(raced->tasks);

      for (i = 0, count = raced->tasks->count; i < count; i++) {
         if ((task = (struct RaceTaskStruct *) RaceFrontList(raced->tasks)) != NULL) {
            RacePopFrontList(raced->tasks);
            RacePushBackList(raced->tasks, task);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaceProcessTaskList returns %d", retn);
#endif
   return (retn);
}


void
RaceLoop(struct RaceDaemonStruct *raced)
{
   struct RaceListStruct *list = NULL;
   int i, cnt;
 
   while (!(RaceShutDownFlag)) {

#ifdef ARGUSDEBUG
      ArgusDebug (7, "RaceLoop: processing");
#endif

      gettimeofday(&raced->now, 0L);

      if (raced->RaceCheckConfFlag) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaceLoop: checking configuration");
#endif
         if ((list = RaceGetTaskList(raced)) != NULL) {
            RaceProcessTaskList(raced, list);
            RaceDeleteTaskList(raced, list);
         }
         raced->RaceCheckConfFlag = 0;
      }

      if (raced->tasks && ((cnt = raced->tasks->count) > 0)) {
         struct RaceTaskStruct *task = NULL;

#ifdef ARGUSDEBUG
         ArgusDebug (3, "RaceLoop checking tasks");
#endif
         for (i = 0; i < cnt; i++) {
            if ((task = (struct RaceTaskStruct *) RaceFrontList(raced->tasks)) != NULL) {
               RacePopFrontList(raced->tasks);
               if (task->pid > 0) {
                  char strbuf[2048];
                  pid_t pid;
                  int status;

                  if ((pid = waitpid(task->pid, &status, WNOHANG | WUNTRACED)) == task->pid) {
                     sprintf (strbuf, "pid %d ", (int)task->pid);

                     if (WIFSTOPPED(status)) {
                        sprintf (&strbuf[strlen(strbuf)], "stopped ");
                        if (task->stoptime.tv_sec == 0) {
                           gettimeofday(&task->stoptime, 0L);
                           ArgusLog (LOG_ALERT, strbuf);

                        } else {
                           if ((raced->now.tv_sec - task->stoptime.tv_sec) > 30) {
                              sprintf (&strbuf[strlen(strbuf)], "greater than 30s ");
                              ArgusLog (LOG_ALERT, strbuf);
                           }
                        }

                     } else {
                        if (WIFEXITED(status)) {
                           sprintf (&strbuf[strlen(strbuf)], "exited with 0x%x ", WEXITSTATUS(status));
                           task->pid = -1;
                        }

                        if (WIFSIGNALED(status)) {
                           sprintf (&strbuf[strlen(strbuf)], "terminated: signal(%d) ", WTERMSIG(status));
                           task->pid = -1;
                        }
#ifdef WCOREDUMP
                        if (WCOREDUMP(status)) {
                           sprintf (&strbuf[strlen(strbuf)], "dumped core ");
                           task->pid = -1;
                        }
#endif

                        ArgusLog (LOG_ALERT, strbuf);
                     }

                  } else {
                     if (pid < 0) {
                        if (errno == ECHILD) {
                           if ((kill (task->pid, 0)) == 0) {
                              char buf[1024], cmd[64], base[64];
                              char *ptr, *str, *bstr;
                              FILE *fp = NULL;
                              int found = 0;

                              if ((str = strncpy (buf, task->program, 1024)) != NULL) {
                                 if ((bstr = basename(str)) != NULL) {
                                    snprintf (base, 64, "%s", bstr);
                                    snprintf (cmd, 64, "ps -p %d", (int) task->pid);
                                    if ((fp = popen(cmd, "r")) != NULL) {
                                       while ((ptr = fgets(buf, 1024, fp)) != NULL) {
                                          if (strstr(ptr, base)) {
                                             found++;
                                             break;
                                          }
                                       }
                                       pclose(fp);
                                    }
                                 }
                              }

                              if (found) {
                                 if (task->pid != -1) {
                                    if (!(task->alarm & RACE_ECHILD_ALARM)) {
                                       ArgusLog (LOG_ALERT, "pid %d owned by another task", (int) task->pid);
                                       task->alarm |= RACE_ECHILD_ALARM;
                                    }
                                 }
                              } else {
                                 ArgusLog (LOG_ALERT, "pid %d is not target task", (int) task->pid);
                                 task->pid = -1;
                              }

                           } else {
                              ArgusLog (LOG_ALERT, "pid %d does not exist", (int) task->pid);
                              task->pid = -1;
                           }
                        }

                     } else {
                        if (task->stoptime.tv_sec != 0) {
                           task->stoptime.tv_sec = 0;
                           ArgusLog (LOG_ALERT, "pid %d restarted", task->pid);
                        }
                     }
                  }
               }

               if (!(task->pid > 0)) {
                  if ((task->pid = fork()) < 0)
                     ArgusLog (LOG_ERR, "fork() error %s", strerror(errno));

                  if (task->pid == 0) {
                     char *args[32], sbuf[1024], *ptr = NULL;
                     int ind = 0;

                     bzero(args, sizeof(args));
                     bzero(sbuf, sizeof(sbuf));

                     args[ind++] = task->program;         

                     if ((ptr = task->params) != NULL) {
                        while (isspace((int)*ptr)) ptr++;
                        if (*ptr != '\0') {
                           args[ind++] = ptr;         
                           while ((ptr = strchr(ptr, ' ')) != NULL) {
                              *ptr++ = '\0';
                              args[ind++] = ptr;
                           }
                        }
                     }

                     for (i = 0; i < 32; i++) {
                        if (args[i] != NULL)
                           sprintf (&sbuf[strlen(sbuf)], " %s", args[i]);
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "spawning %s ", sbuf);
#endif
                     if (!(raced->debug & RACE_DEBUGTASKMASK)) {
                        exit(execv(task->program, args));

                     } else {
                        sleep(1);
                        exit(1);
                     }

                  } else {
                     char sbuf[1024], tbuf[64];
                     time_t secs = raced->now.tv_sec;

                     ArgusLog (LOG_ALERT, "RaceProcessTaskList: New task[%d]: project %s.%s task %d '%s'",
                           task->pid, task->project, task->type, task->tasknum, task->program);

                     if (strftime(tbuf, 64, "%Y-%m-%d %H:%M:%S", localtime(&secs)) <= 0)
                        ArgusLog(LOG_ERR, "strftime: error %s", strerror(errno));
                     
                     sprintf (sbuf, "UPDATE Tasks set pid=%d,date=\"%s\",status=1 where id=%d", (int) task->pid, tbuf, task->id);

#if defined(ARGUS_MYSQL)
                     if (mysql_real_query(&mysql, sbuf, strlen(sbuf)) != 0)
                        ArgusLog(LOG_ERR, "mysql: %s error %s", sbuf, mysql_error(&mysql));
#endif
                  }
               }

               RacePushBackList(raced->tasks, task);
            }
         }
      }

      usleep(1000000);
      raced->RaceCheckConfFlag++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "exiting");
#endif

   if (raced->tasks && ((cnt = raced->tasks->count) > 0)) {
      struct RaceTaskStruct *task = NULL;
      for (i = 0; i < cnt; i++) {
         if ((task = (struct RaceTaskStruct *) RaceFrontList(raced->tasks)) != NULL) {

            RacePopFrontList(raced->tasks);

            if (task->pid > 0) {
               char sbuf[1024], tbuf[64];
               time_t secs;
               int status;
#if defined(ARGUS_MYSQL)
               int retn;
#endif
#ifdef ARGUSDEBUG
               ArgusDebug (2, "killing pid %d", task->pid);
#endif
               if (!(kill (task->pid, SIGINT)))
                  waitpid (task->pid, &status, 0);

               ArgusLog (LOG_ALERT, "RaceProcessTaskList: Killed task[%d]: project %s.%s task %d '%s'",
                           task->pid, task->project, task->type, task->tasknum, task->program);

               gettimeofday(&raced->now, 0L);
               secs = raced->now.tv_sec;
               if (strftime(tbuf, 64, "%Y-%m-%d %H:%M:%S", localtime(&secs)) <= 0)
                  ArgusLog(LOG_ERR, "strftime: error %s", strerror(errno));
                     
               sprintf (sbuf, "UPDATE Tasks set status=0,date=\"%s\" where id=%d", tbuf, task->id);

#if defined(ARGUS_MYSQL)
               if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_ERR, "mysql: %s error %s", sbuf, mysql_error(&mysql));
#endif
            }

            RaceDeleteTask(raced, task);
         }
      }
   }
}


void
RaceUsr1Sig (int val)
{
   struct RaceDaemonStruct *raced = RaceDaemon;

   if (raced != NULL) {
      int value = raced->debugflag;
      raced->debugflag = (value > 15) ? 15 : value + 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceUsr1Sig(%d)", val);
#endif
}

void
RaceUsr2Sig (int val)
{
   struct RaceDaemonStruct *raced = RaceDaemon;

   if (raced != NULL) {
      int value = raced->debugflag;
      raced->debugflag = (value == 0) ? 0 : value - 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceUsr2Sig(%d)", val);
#endif
}

void
RaceHupSig (int val)
{
   struct RaceDaemonStruct *raced = RaceDaemon;

   if (raced != NULL) {
      if (raced->daemonflag) {
         ArgusLog (LOG_ALERT, "RaceHupSig (%d) signal received", val);
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaceHupSig (%d) signal received", val);
#endif
      }

      if (raced->RaceChildPid) {
         if (getpid() != raced->RaceChildPid)
            kill (raced->RaceChildPid, SIGHUP);
      } else
         raced->RaceCheckConfFlag++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceHupSig(%d)", val);
#endif
}

void
RaceShutDown (int val)
{
   struct RaceDaemonStruct *raced = RaceDaemon;
 
   RaceShutDownFlag++;

   if (raced != NULL) {
      if (raced->daemonflag) {
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaceShutDown (%d)", val);
#endif
      }
 
      if (raced->RaceChildPid) {
         if (getpid() != raced->RaceChildPid) {
            kill (raced->RaceChildPid, val);
         }
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaceShutDown (%d) done", val);
#endif
}

int
RaceCheckDatabases(struct RaceDaemonStruct *raced)
{
   int retn = 0;
#if defined(ARGUS_MYSQL)
   int i;
   int x;
   char sbuf[256];

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaceDataBase);
#ifdef ARGUSDEBUG
   ArgusDebug (3, "mysql_real_query() %s\n", sbuf);
#endif

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql: %s error %s", sbuf, mysql_error(&mysql));

   sprintf (sbuf, "USE %s", RaceDataBase);
#ifdef ARGUSDEBUG
   ArgusDebug (3, "mysql_real_query() %s\n", sbuf);
#endif

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql: %s error %s", sbuf, mysql_error(&mysql));

   if ((mysqlRes = mysql_list_tables(&mysql, NULL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int index = 0;
 
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
 
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));

            for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");
 
            for (i = 0; i < RA_MAXTABLES; i++) {
               if (!(strcmp(sbuf, RaceCreateTableNames[i]))) {
                  RaceExistsTableNames[index++] = strdup (sbuf);
                  RaceTableFlags |= (0x01 << i);
                  break;
               }
            }
         }
 
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (8, "mysql_num_fields() returned zero.\n");
#endif
      }
 
      mysql_free_result(mysqlRes);
   }

   if (RaceTableFlags != RA_MAXTABLES_MASK) {
      for (i = 0; i < RA_MAXTABLES; i++) {
         if (!(RaceTableFlags & (0x01 << i))) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "generating table %s\n", RaceCreateTableNames[i]);
#endif
            if ((retn = mysql_real_query(&mysql, RaceTableCreationString[i],
                                       strlen(RaceTableCreationString[i]))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));
         }
      }
   }
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaceCheckDatabases(0x%x) returns %d", raced, retn);
#endif
   return (retn);
}


extern char version[];

void
usage ()
{
   fprintf (stderr, "raced Version %s\n", version);
   fprintf (stderr, "usage: %s [options]\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -u <username> specify account used to connect to db.\n");
   fprintf (stderr, "         -p <password> specify the password for the account.\n");
   fprintf (stderr, "         -U <newuser>  create new RACE account for this node.\n");

   exit(1);
}


char RacePrintTimeBuf[64];
char *RaceTimeFormat = "%T";

char *
print_time(struct timeval *tvp)
{
   char timeZoneBuf[32];
   char *retn = RacePrintTimeBuf, *ptr;
   time_t secs = tvp->tv_sec;
   int pflag = 6;
   struct tm *tm;

   bzero (timeZoneBuf, sizeof(timeZoneBuf));
   bzero (RacePrintTimeBuf, sizeof(RacePrintTimeBuf));

   if ((tm = localtime (&secs)) == NULL)
      return (NULL);
   
   if ((strftime ((char *) retn, 64, RaceTimeFormat, tm)) == 0)
      ArgusLog (LOG_ERR, "print_time: format %s not supported.\n", RaceTimeFormat);

   if (pflag) {
      ptr = &retn[strlen(retn)];
      sprintf (ptr, ".%06d", (int) tvp->tv_usec);
      ptr[pflag + 1] = '\0';
   }


   return (retn);
}


#define RACE_RCITEMS				3

#define RA_DB_USER				0
#define RA_DB_PASS				1
#define RA_DATABASE				2

#define RA_TASK					3

char *RaceResourceFileStr [] = {
   "RA_DB_USER=",
   "RA_DB_PASS=",
   "RA_DATABASE=",
   "RA_TASK=",
};


int
RaceParseResourceFile (char *file)
{
   int retn = 0, i, len;

   char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL, *ptr;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         retn = 1;
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               for (i = 0; i < RACE_RCITEMS; i++) {
                  len = strlen(RaceResourceFileStr[i]);
                  if (!(strncmp (str, RaceResourceFileStr[i], len))) {

                     optarg = &str[len];

                     if (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';

                     if (*optarg == '\"')
                        optarg++;

                     if (optarg[strlen(optarg) - 1] == '\"')
                        optarg[strlen(optarg) - 1] = '\0';
                        
                     if (*optarg == '\0')
                        optarg = NULL;

                     if (optarg) {
                        switch (i) {
                           case RA_DB_USER:
                              if (RaceUser != NULL)
                                 free(RaceUser);
                              RaceUser = strdup(optarg);
                              if ((ptr = strchr (RaceUser, '/')) != NULL)
                                 *ptr = '\0';
                              break;

                           case RA_DB_PASS:
                              if (RacePass != NULL)
                                 free(RacePass);
                              RacePass = strdup(optarg);
                              break;

                           case RA_DATABASE:
                              break;
                           case RA_TASK:
                              break;
                        }
                     }
                     break;
                  }
               }
            }
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "%s: %s\n", file, strerror(errno));
#endif
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaceParseResourceFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}

void RaceWindowClose(void);
void RaceWindowClose(void) { }
 

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include "global.h"
#include "md5.h"

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

void MD5Init (MD5_CTX *);
void MD5Update ( MD5_CTX *, unsigned char *, unsigned int);
void MD5Final (unsigned char [16], MD5_CTX *);

static void MD5Transform (UINT4 [4], unsigned char [64]);
static void Encode (unsigned char *, UINT4 *, unsigned int);
static void Decode (UINT4 *, unsigned char *, unsigned int);
static void MD5_memcpy (POINTER, POINTER, unsigned int);
static void MD5_memset (POINTER, int, unsigned int);

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void
MD5Init (MD5_CTX *context)
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.  */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void
MD5Update ( MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((UINT4)inputLen << 3))
   < ((UINT4)inputLen << 3))
 context->count[1]++;
  context->count[1] += ((UINT4)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible.
*/
  if (inputLen >= partLen) {
 MD5_memcpy
   ((POINTER)&context->buffer[index], (POINTER)input, partLen);
 MD5Transform (context->state, context->buffer);

 for (i = partLen; i + 63 < inputLen; i += 64)
   MD5Transform (context->state, &input[i]);

 index = 0;
  }
  else
 i = 0;

  /* Buffer remaining input */
  MD5_memcpy
 ((POINTER)&context->buffer[index], (POINTER)&input[i],
  inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void
MD5Final (unsigned char digest[16], MD5_CTX *context)
{
  unsigned char bits[8];
  unsigned int index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.  */
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information.
*/
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static
void MD5Transform (UINT4 state[4], unsigned char block[64])
{
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
 */
  MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void 
Encode ( unsigned char *output, UINT4 *input, unsigned int len)
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
 output[j] = (unsigned char)(input[i] & 0xff);
 output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void 
Decode ( UINT4 *output, unsigned char *input, unsigned int len)
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
   (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void 
MD5_memcpy ( POINTER output, POINTER input, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
 output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void
MD5_memset ( POINTER output, int value, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}


/* MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
rights reserved.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* The following makes MD default to MD5 if it has not already been
  defined with C compiler flags.
 */

#ifndef MD
#define MD 5
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "global.h"
#if MD == 2
#include "md2.h"
#endif
#if MD == 4
#include "md4.h"
#endif
#if MD == 5
#include "md5.h"
#endif


#if MD == 2
#define MD_CTX MD2_CTX
#define MDInit MD2Init
#define MDUpdate MD2Update
#define MDFinal MD2Final
#endif
#if MD == 4
#define MD_CTX MD4_CTX
#define MDInit MD4Init
#define MDUpdate MD4Update
#define MDFinal MD4Final
#endif
#if MD == 5
#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
#endif

/* 
   Digests a file and prints the result.
 */


char MDFileBuf[128];

char *
MDString (char *str)
{
  unsigned char digest[16];
  unsigned char buffer[1024];
  MD_CTX context;
  int i;

  bzero (MDFileBuf, sizeof(MDFileBuf));
  bzero (buffer, sizeof(buffer));
  sprintf ((char *)buffer, "%s", str);

  MDInit (&context);
  MDUpdate (&context, buffer, strlen((char *)buffer));
  MDFinal (digest, &context);

  for (i = 0; i < 16; i++)
     sprintf (&MDFileBuf[strlen(MDFileBuf)], "%02x", digest[i]);

  return(MDFileBuf);
}


void
RaceDeleteTaskList (struct RaceDaemonStruct *raced,  struct RaceListStruct *list)
{
   struct RaceTaskStruct *task = NULL;
   int i, count;

   if (list != NULL) {
      for (i = 0, count = list->count; i < count; i++) {
         if ((task = (struct RaceTaskStruct *) RaceFrontList(list)) != NULL) {
            RaceDeleteTask(raced, task);
            RacePopFrontList(list);
         }
      }

      RaceDeleteList(list);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "RaceDeleteTaskList (0x%x, 0x%x) returning\n", raced, list);
#endif
}


struct RaceListStruct *
RaceNewList ()
{
   struct RaceListStruct *retn = NULL;
 
   if ((retn = (struct RaceListStruct *) ArgusCalloc (1, sizeof (struct RaceListStruct))) != NULL) {
      retn->start = NULL;
      retn->count = 0;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "RaceNewList () returning 0x%x\n", retn);
#endif

   return (retn);
}

void
RaceDeleteList (struct RaceListStruct *list)
{
   if (list) {
      while (list->start) {
         RacePopFrontList(list);
      }

      ArgusFree (list);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "RaceDeleteList (0x%x) returning\n", list);
#endif
}


int
RaceListEmpty (struct RaceListStruct *list)
{
   return (list->start == NULL);
}


int
RaceGetListCount(struct RaceListStruct *list)
{
   return (list->count);
}


void
RacePushFrontList(struct RaceListStruct *list, void *obj)
{
   struct RaceListObjectStruct *lobj = NULL;

   if (list && obj) {
      if ((lobj = (struct RaceListObjectStruct *) ArgusCalloc (1, sizeof(*lobj))) != NULL) {
         lobj->obj = obj;
   
         if (list->start) {
            lobj->nxt = list->start;
            lobj->prv = list->start->prv;
            lobj->nxt->prv = lobj;
            lobj->prv->nxt = lobj;
         } else {
            lobj->prv = lobj;
            lobj->nxt = lobj;
         }
   
         list->start = lobj;
         list->count++;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RacePushFrontList (0x%x, 0x%x) returning 0x%x\n", list, obj);
#endif
}


void
RacePushBackList(struct RaceListStruct *list, void *obj)
{
   RacePushFrontList(list, obj);
   list->start = list->start->nxt;

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RacePushBackList (0x%x, 0x%x) returning 0x%x\n", list, obj);
#endif
}

void *
RaceFrontList(struct RaceListStruct *list)
{
   void *retn = NULL;

   if (list->start)
      retn = list->start->obj;

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaceFrontList (0x%x) returning 0x%x\n", list, retn);
#endif

   return (retn);
}


void *
RaceBackList(struct RaceListStruct *list)
{
   void *retn = NULL;

   if (list->start)
      retn = list->start->prv->obj;

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaceBackList (0x%x) returning 0x%x\n", list, retn);
#endif

   return (retn);
}


void
RacePopBackList(struct RaceListStruct *list)
{
   struct RaceListObjectStruct *lobj = NULL;

   if ((lobj = list->start)) {
      list->start = list->start->prv;
      RacePopFrontList(list);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RacePopBackList (0x%x) returning\n", list);
#endif
}

int RaceListSortRoutine (const void *, const void *);

int
RaceListSortRoutine (const void *void1, const void *void2)
{
   int retn = 0;
   struct RaceTaskStruct *t1 = *(struct RaceTaskStruct **)void1;
   struct RaceTaskStruct *t2 = *(struct RaceTaskStruct **)void2;

   if (t1 && t2)
      if ((retn = strcmp(t1->project, t2->project)) == 0)
         retn = (t1->tasknum > t2->tasknum) ? 1 : -1;

   return (retn);
}

void
RaceSortList(struct RaceListStruct *list)
{
   int i = 0, cnt; 
   void **array = NULL;
 
   if ((list != NULL) && ((cnt = list->count) > 0)) {
      if ((array = ArgusCalloc(sizeof(void *), cnt + 1)) == NULL)
         ArgusLog (LOG_ERR, "RaceSortList: ArgusCalloc(%d, %d) %s", sizeof(void *), cnt + 1, strerror(errno));

      for (i = 0; i < cnt; i++) {
         array[i] = RaceFrontList(list);
         RacePopFrontList(list);
      } 
 
      qsort ((char *) array, cnt, sizeof (struct RaceTaskStruct *), RaceListSortRoutine);
 
      for (i = 0; i < cnt; i++)
         RacePushBackList(list, array[i]);

      ArgusFree(array);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaceSortList (0x%x) returning\n", list);
#endif
}



struct RaceListStruct *
RaceGetChangeList(struct RaceListStruct *l1, struct RaceListStruct *l2)
{
   struct RaceListStruct *list = NULL;

   if (l1 && l2) {
      if (RaceListCmp(l1, l2)) {
         struct RaceListObjectStruct *lo2;
         struct RaceTaskStruct *t1, *t2;
         int cnt, i, retn;

         if ((list = RaceNewList()) == NULL)
            ArgusLog (LOG_ERR, "RaceGetChangeList: RaceNewList error %s", strerror(errno));

         for (i = 0, cnt = l1->count; i < cnt; i++) {
            if ((t1 = (struct RaceTaskStruct *) RaceFrontList(l1)) != NULL) {
               RacePopFrontList(l1);
               if ((lo2 = l2->start) != NULL) {
                  t2 = (void *)lo2->obj;
                  do {
                     if (!(retn = strcmp(t1->project, t2->project)))
                     if (!(retn = (t1->tasknum - t2->tasknum)))
                     if (!(retn = strcmp(t1->program, t2->program)))
                     if (!(retn = strcmp(t1->params,  t2->params)))
                     if (!(retn = strcmp(t1->type,    t2->type)))
                           retn = strcmp(t1->dir,     t2->dir);
                     lo2 = lo2->nxt;
                     t2 = (void *)lo2->obj;
                  } while ((lo2 != l2->start) && retn);

                  if (retn) {
                     RacePushBackList(list, t1);
                  } else
                     RacePushBackList(l1, t1);

               } else {
                  RacePushBackList(list, t1);
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaceGetChangeList (0x%x, 0x%x) returning 0x%x", l1, l2, list);
#endif
   return (list);
}

struct RaceListStruct *
RaceMergeList(struct RaceDaemonStruct *raced, struct RaceListStruct *l1, struct RaceListStruct *l2)
{
   struct RaceListObjectStruct *lo1;
   struct RaceTaskStruct *t1, *t2;
   int cnt, i, retn;

   if (l1 && l2 && ((cnt = l2->count) > 0)) {
      for (i = 0; i < cnt; i++) {
         if ((t2 = (struct RaceTaskStruct *) RaceFrontList(l2)) != NULL) {
            RacePopFrontList(l2);
            lo1 = l1->start;
            t1 = (void *)lo1->obj;
            do {
               if (!(retn = strcmp(t1->project, t2->project)))
               if (!(retn = (t1->tasknum - t2->tasknum)))
               if (!(retn = strcmp(t1->program, t2->program)))
               if (!(retn = strcmp(t1->params,  t2->params)))
                     retn = strcmp(t1->dir,     t2->dir);
               lo1 = lo1->nxt;
               t1 = (void *)lo1->obj;
            } while ((lo1 != l1->start) && retn);
   
            if (!retn) {
               RaceDeleteTask(raced, t2);
            } else
               RacePushBackList(l2, t2);
         }
      }

      while (!(RaceListEmpty (l2))) {
         t2 = RaceFrontList(l2);
         RacePopFrontList(l2);
         RacePushBackList(l1, t2);
      }

      RaceSortList(l1);
   }

   return (l1);
}


int
RaceListCmp(struct RaceListStruct *l1, struct RaceListStruct *l2)
{
   int retn = 0, i, cnt;

   if (l1 && l2 && (l1->count == l2->count)) {
      struct RaceListObjectStruct *lo1 = l1->start, *lo2 = l2->start;
      struct RaceTaskStruct *t1 = (void *)lo1->obj, *t2 = (void *)lo2->obj;

      for (i = 0, cnt = l1->count; (i < cnt) && !retn; i++) {
         if (!(retn = strcmp(t1->project, t2->project)))
         if (!(retn = (t1->tasknum - t2->tasknum)))
         if (!(retn = strcmp(t1->program, t2->program)))
         if (!(retn = strcmp(t1->params,  t2->params)))
               retn = strcmp(t1->dir,     t2->dir);

         if (retn == 0) {
            if ((lo1 = lo1->nxt) != NULL)
               t1 = (void *) lo1->obj;
            if ((lo2 = lo2->nxt) != NULL)
               t2 = (void *) lo2->obj;
         }
      }

   } else
      retn = (l1->count - l2->count);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaceListCmp (0x%x, 0x%x) returning %d", l1, l2, retn);
#endif
   return (retn);
}

void
RacePopFrontList(struct RaceListStruct *list)
{
   struct RaceListObjectStruct *lobj = NULL;

   if ((lobj = list->start)) {
      if (--list->count > 0) {
         if (lobj->prv)
            lobj->prv->nxt = lobj->nxt;
 
         if (lobj->nxt)
            lobj->nxt->prv = lobj->prv;
 
        list->start = lobj->nxt;
 
      } else
         list->start = NULL;
 
      ArgusFree(lobj);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RacePopFrontList (0x%x) returning\n", list);
#endif
}


int
RaceAddModeList (struct RaceDaemonStruct *raced, char *ptr)
{
   int retn = 0;
   struct RaceModeStruct *mode, *list;

   if (ptr) {
      if ((mode = (struct RaceModeStruct *) ArgusCalloc (1, sizeof(struct RaceModeStruct))) != NULL) {
         if ((list = raced->RaceModeList) != NULL) {
            while (list->nxt)
               list = list->nxt;
            list->nxt = mode;
         } else
            raced->RaceModeList = mode;

         mode->mode = strdup(ptr);
         retn = 1;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "RaceAddModeList (0x%x, %s) returning %d\n", raced, ptr, retn);
#endif

   return (retn);
}

void
RaceDeleteModeList (struct RaceDaemonStruct *raced)
{

   if (raced && raced->RaceModeList) {
      struct RaceModeStruct *mode = raced->RaceModeList;

      while (mode) {
        if (mode->mode)
           free(mode->mode);

        mode = mode->nxt;
        ArgusFree(raced->RaceModeList);
        raced->RaceModeList = mode;
      }
   }

#ifdef ARGUSDEBUG 
   ArgusDebug (2, "ArgusDeleteModeList () returning\n");
#endif
}


void ArgusClientTimeout () { return; }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { return; }
void RaArgusInputComplete (struct ArgusInput *input) { return; }
void ArgusWindowClose(void) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if ((sig == SIGINT) || (sig == SIGQUIT))
         exit(0);
   }
}
