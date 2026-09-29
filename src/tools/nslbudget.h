/*
 * nslookup's wait budget: TIMEOUT seconds over NSL_ATTEMPTS sends, as
 * 200 ms select() slices.  Five slices a second, spread so the three
 * attempts add up to exactly secs * 5 (F-170).  This is a nominal
 * select-wait budget, not a wall-clock deadline.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_NSLBUDGET_H
#define AMINETXDUO_NSLBUDGET_H

/* Slices for attempt `tries` (0-based) of `attempts`, secs >= 1.  Every
   product stays below 2^32 for any secs that fits a positive LONG. */
static inline unsigned long nsl_slices(unsigned long secs, unsigned long attempts,
                                       unsigned long tries)
{
    unsigned long per = (secs / attempts) * 5UL +
                        ((secs % attempts) * 5UL) / attempts;
    unsigned long rem = ((secs % attempts) * 5UL) % attempts;

    return per + ((tries < rem) ? 1UL : 0UL);
}

#endif
