/*
 * F-301: tls_time.c against a DateStamp() this test sets.  A day count is
 * bounded before it is multiplied, so a clock 136 years out -- days * 86400
 * wrapping in 32 bits -- is not taken as a date inside the window, and nor is
 * a field no DateStamp() should hold.  tls_time_monotonic() is unchanged:
 * the plain sum tls_resume.c ages sessions by.
 *
 * SPDX-License-Identifier: MIT
 */

#include "tls_internal.h"

#include <stdio.h>

struct DosLibrary *DOSBase = (struct DosLibrary *)1;

static struct DateStamp clock_now;

struct DateStamp *DateStamp(struct DateStamp *ds)
{
    *ds = clock_now;
    return ds;
}

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

#define DAY_2027        17897L              /* 1978-01-01 + 17897 = 2027-01-01 */
#define UNIX_2027       1798761600UL
#define WRAP_DAYS       49711L              /* 49711 * 86400 = 2^32 + 63104 */

static void set_clock(long days, long minute, long tick)
{
    clock_now.ds_Days   = days;
    clock_now.ds_Minute = minute;
    clock_now.ds_Tick   = tick;
}

int main(void)
{
    /* A date inside the window is known and exact. */
    set_clock(DAY_2027, 0, 0);
    CHECK(tls_time_is_known());
    CHECK(tls_time_now() == UNIX_2027);
    set_clock(DAY_2027, 90, 150);
    CHECK(tls_time_now() == UNIX_2027 + 90UL * 60UL + 3UL);

    /* THE CASE: 49711 days on, the 32-bit sum wraps to 17.5 hours past
       2027-01-01.  It is 2163, not 2027, and not a date to check with. */
    set_clock(DAY_2027 + WRAP_DAYS, 0, 0);
    CHECK(tls_time_monotonic() == UNIX_2027 + 63104UL);  /* the sum, as before */
    CHECK(!tls_time_is_known());
    CHECK(tls_time_now() == 0);

    /* The largest count a LONG holds. */
    set_clock(0x7fffffffL, 0, 0);
    CHECK(!tls_time_is_known());
    CHECK(tls_time_now() == 0);

    /* Fields no DateStamp() holds. */
    set_clock(DAY_2027, 1440, 0);
    CHECK(tls_time_now() == 0);
    set_clock(DAY_2027, 0, 3000);
    CHECK(tls_time_now() == 0);
    set_clock(-1, 0, 0);
    CHECK(tls_time_now() == 0);

    /* Before the floor: an uptime, not a date. */
    set_clock(3, 0, 0);
    CHECK(!tls_time_is_known());
    CHECK(tls_time_monotonic() == 252460800UL + 3UL * 86400UL);

    /* No dos.library: nothing. */
    DOSBase = NULL;
    set_clock(DAY_2027, 0, 0);
    CHECK(tls_time_now() == 0);
    CHECK(tls_time_monotonic() == 0);

    printf("RESULT tls_time checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
