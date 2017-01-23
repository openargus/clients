#ifndef __UNITTEST_H
# define __UNITTEST_H

# include <stdio.h>

static const char *PASS = "pass";
static const char *FAIL = "fail";
static const char *SEPARATOR = "====";

static unsigned __unittest_num = 0;
static unsigned __unittest_failed = 0;

static inline void
TestReset(void)
{
   __unittest_num = 0;
   __unittest_failed = 0;
}

static inline void
TestSectionHeading(const char * const heading)
{
   printf("\n%s\n", heading);
}

static inline void
TestHeading(const char * const heading)
{
   printf(" %2d. %-50.50s . . . ", __unittest_num++, heading);
   fflush(stdout);
}

static inline void
TestResult(int cond)
{
   printf("%s\n", cond ? PASS : FAIL);
   if (!cond)
      __unittest_failed++;
}

static inline int
TestSummary(void)
{
   printf("\n%s\n\n", SEPARATOR);
   printf("Summary: %u of %u tests passed (%u failed)\n",
          (__unittest_num - __unittest_failed),
          __unittest_num,
          __unittest_failed);

   return __unittest_failed ? -1 : 0;
}

#endif
