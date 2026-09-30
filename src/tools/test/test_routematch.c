/*
 * DeleteNetRoute's lookup of a route added by hand (F-133): bare 0.0.0.0
 * finds a static /0, an explicit mask needs an exact static row, a static /0
 * never stands in for a more specific route, and the live default gateway is
 * never a match.
 *
 * SPDX-License-Identifier: MIT
 */
#include "routematch.h"

#include <stdio.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

#define IP(a, b, c, d)  (((ULONG)(a) << 24) | ((ULONG)(b) << 16) | \
                         ((ULONG)(c) << 8) | (ULONG)(d))

#define LIVE_GW     { 0, 0, IP(192,168,1,1), NETSTATUS_RT_UP | NETSTATUS_RT_GATEWAY, 0 }
#define IFACE       { IP(192,168,1,0), IP(255,255,255,0), 0, NETSTATUS_RT_UP, 0 }
#define STATIC_0    { 0, 0, IP(192,168,1,2), \
                      NETSTATUS_RT_UP | NETSTATUS_RT_STATIC | NETSTATUS_RT_GATEWAY, 0 }
#define STATIC_77   { IP(192,168,77,0), IP(255,255,255,0), IP(192,168,1,3), \
                      NETSTATUS_RT_UP | NETSTATUS_RT_STATIC | NETSTATUS_RT_GATEWAY, 0 }

int main(void)
{
    {   /* A static /0 listed before a more specific static route. */
        const NetStatusRoute r[] = { IFACE, STATIC_0, STATIC_77, LIVE_GW };
        const LONG n = 4;

        CHECK(route_match_static(r, n, 0, 0, FALSE) == 1);          /* bare 0.0.0.0 */
        CHECK(route_match_static(r, n, 0, 0, TRUE) == 1);           /* 0.0.0.0/0 */
        CHECK(route_match_static(r, n, IP(192,168,77,5), 0, FALSE) == 2);
        CHECK(route_match_static(r, n, IP(192,168,77,0), 0, FALSE) == 2);
        CHECK(route_match_static(r, n, IP(10,1,2,3), 0, FALSE) == -1);
        CHECK(route_match_static(r, n, IP(192,168,1,9), 0, FALSE) == -1);
        CHECK(route_match_static(r, n, IP(192,168,77,0), IP(255,255,255,0), TRUE) == 2);
        CHECK(route_match_static(r, n, IP(192,168,77,5), IP(255,255,255,0), TRUE) == 2);
        CHECK(route_match_static(r, n, IP(192,168,77,0), IP(255,255,255,128), TRUE) == -1);
        CHECK(route_match_static(r, n, IP(192,168,1,0), IP(255,255,255,0), TRUE) == -1);
    }
    {   /* The same, the static /0 listed last. */
        const NetStatusRoute r[] = { LIVE_GW, STATIC_77, IFACE, STATIC_0 };
        const LONG n = 4;

        CHECK(route_match_static(r, n, 0, 0, FALSE) == 3);
        CHECK(route_match_static(r, n, 0, 0, TRUE) == 3);
        CHECK(route_match_static(r, n, IP(192,168,77,5), 0, FALSE) == 1);
    }
    {   /* Nothing added by hand: only the live gateway and the interface.
           NetX reports success deleting from this empty table. */
        const NetStatusRoute r[] = { IFACE, LIVE_GW };
        const LONG n = 2;

        CHECK(route_match_static(r, n, 0, 0, FALSE) == -1);
        CHECK(route_match_static(r, n, 0, 0, TRUE) == -1);
        CHECK(route_match_static(r, n, IP(192,168,77,0), IP(255,255,255,0), TRUE) == -1);
        CHECK(route_match_static(r, n, IP(192,168,1,0), IP(255,255,255,0), TRUE) == -1);
    }
    {   /* No answer at all. */
        CHECK(route_match_static(NULL, 0, 0, 0, TRUE) == -1);
        CHECK(route_match_static(NULL, 0, IP(192,168,77,5), 0, FALSE) == -1);
    }

    printf("RESULT route_match checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
