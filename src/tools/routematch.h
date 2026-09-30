/*
 * AddNetRoute/DeleteNetRoute: which NETSTATUS_ROUTES row is a route added by
 * hand, kept apart so the host can test it.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_ROUTEMATCH_H
#define AMINETXDUO_ROUTEMATCH_H

#include <aminetxduo/netstatus.h>

/*
 * The static row for dest, or -1.  With a mask (have_mask), only the row with
 * exactly that destination and mask: NetX reports success deleting from an
 * empty table, so nothing else may reach it (F-133).  Without, the first
 * static row that carries dest; a /0 row only for 0.0.0.0 itself, so it never
 * stands in for a more specific route.  The live default gateway is listed
 * without NETSTATUS_RT_STATIC and never matches.
 */
static inline LONG route_match_static(const NetStatusRoute *r, LONG n,
                                      ULONG dest, ULONG mask, BOOL have_mask)
{
    LONG i;

    for (i = 0; i < n; i++)
    {
        if (!(r[i].nsr_Flags & NETSTATUS_RT_STATIC))
            continue;

        if (have_mask || dest == 0)
        {
            ULONG want = have_mask ? mask : 0;

            if (r[i].nsr_NetMask == want &&
                r[i].nsr_Destination == (dest & want))
                return i;
        }
    }

    if (have_mask)
        return -1;

    for (i = 0; i < n; i++)
    {
        if (r[i].nsr_NetMask == 0)
            continue;
        if (!(r[i].nsr_Flags & NETSTATUS_RT_STATIC))
            continue;
        if ((dest & r[i].nsr_NetMask) != r[i].nsr_Destination)
            continue;
        return i;
    }

    return -1;
}

#endif
