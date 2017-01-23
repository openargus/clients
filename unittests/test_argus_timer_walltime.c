#include "argus_config.h"
#include "argus_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unittest.h"
#include "test_argus_timer.h"

int main(int argc, char **argv, char **env)
{

   unsigned slots = 40;
   struct timespec duration = {0, 1000000}; /* 1 ms */
   struct timespec period = {0, 250000000}; /* 1/4 second */

   return runtests(slots, &period, &duration, NULL, NULL);
}
