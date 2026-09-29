/*
 * nslookup's TIMEOUT as 200 ms slices over three attempts (F-170).  It used
 * to be secs / 3 per attempt, at least 1: TIMEOUT=1 waited 3 s and the
 * default 10 waited 9 s.  The slices must add up to exactly secs * 5.
 *
 * SPDX-License-Identifier: MIT
 */
#include "nslbudget.h"

#include <stdio.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static unsigned long total(unsigned long secs)
{
    return nsl_slices(secs, 3, 0) + nsl_slices(secs, 3, 1) + nsl_slices(secs, 3, 2);
}

int main(void)
{
    unsigned long s;

    CHECK(nsl_slices(1, 3, 0) == 2 && nsl_slices(1, 3, 1) == 2 && nsl_slices(1, 3, 2) == 1);
    CHECK(nsl_slices(2, 3, 0) == 4 && nsl_slices(2, 3, 1) == 3 && nsl_slices(2, 3, 2) == 3);
    CHECK(nsl_slices(10, 3, 0) == 17 && nsl_slices(10, 3, 1) == 17 && nsl_slices(10, 3, 2) == 16);
    CHECK(nsl_slices(3, 3, 0) == 5 && nsl_slices(3, 3, 2) == 5);

    for (s = 1; s <= 1000; s++)
        CHECK(total(s) == s * 5UL);

    /* The largest positive LONG does not wrap in 32 bits. */
    CHECK(nsl_slices(2147483647UL, 3, 0) == 3579139412UL);
    CHECK(total(2147483647UL) == 2147483647UL * 5UL ||
          sizeof(unsigned long) == 4);

    printf("nslbudget: %d checks, %d failure(s)\n", checks, failures);
    return failures != 0;
}
