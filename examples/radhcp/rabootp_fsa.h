#ifndef __RABOOTP_FSA_H
# define __RABOOTP_FSA_H
# include "argus_config.h"
# include "rabootp.h"

typedef int (*statefunc)(const struct ArgusDhcpStruct * const parsed,
                         const struct ArgusDhcpStruct * const cached);


/* fsa_choose_initial_state:
 *   Expects the first DHCP message observed for this transaction
 *   and examines the newly parsed dhcp structure to determine where
 *   in the client state machine (rfc2131 figure 5) to start out.
 *   There are a number of reasons why we might not see the entire
 *   exchange so no assumption can be made about starting in the
 *   INIT state.  Returns the chosen state as an integer.
 */
int fsa_choose_initial_state(const struct ArgusDhcpStruct * const);


/* fsa_advance_state:
 *
 * Given the currently cached state for this transaction and a
 * freshly parsed DHCP message, determine what the next state should
 * be.  The next state may be the same as the current state.  Returns
 * the next state as an integer.
 */
int fsa_advance_state(const struct ArgusDhcpStruct * const,
                      const struct ArgusDhcpStruct * const);

#endif
