/*
 * paysum's verdict on one connection, kept apart so the host can test it.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_PAYVERDICT_H
#define AMINETXDUO_PAYVERDICT_H

/*
 * Nonzero when the connection counts as a failure: it failed outright; a
 * verified receive saw a wrong byte; or it moved a count other than LEN.
 * LEN 0 is "to EOF" on receive and asks nothing of the count.  Sends always
 * carry a LEN.  A receive with a LEN used to pass on any clean count, so a
 * short transfer read as fails=0 (F-174).
 */
static inline int pay_conn_fails(int failed, int verify, int send,
                                 long first_bad, unsigned long moved,
                                 unsigned long len)
{
    if (failed)
        return 1;
    if (verify && !send && first_bad >= 0)
        return 1;
    if (send && moved != len)
        return 1;
    if (!send && len != 0 && moved != len)
        return 1;
    return 0;
}

#endif
