/*
 * paysum's per-connection verdict (F-174): a receive with LEN must move
 * exactly LEN; LEN 0 is to EOF; the send and verification rules stay.
 *
 * SPDX-License-Identifier: MIT
 */
#include "payverdict.h"

#include <stdio.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

int main(void)
{
    /* failed, verify, send, first_bad, moved, len */

    /* Receive with LEN: exactly LEN passes, short or long fails. */
    CHECK(pay_conn_fails(0, 0, 0, -1, 1000, 1000) == 0);
    CHECK(pay_conn_fails(0, 0, 0, -1,  999, 1000) == 1);
    CHECK(pay_conn_fails(0, 0, 0, -1, 1001, 1000) == 1);
    CHECK(pay_conn_fails(0, 1, 0, -1,  500, 1000) == 1);   /* verified, short */

    /* Receive to EOF: any clean count passes, including none. */
    CHECK(pay_conn_fails(0, 0, 0, -1, 12345, 0) == 0);
    CHECK(pay_conn_fails(0, 0, 0, -1, 0, 0) == 0);

    /* Verification and outright failure, as before. */
    CHECK(pay_conn_fails(0, 1, 0, 17, 1000, 1000) == 1);
    CHECK(pay_conn_fails(0, 1, 0, 17, 1000, 0) == 1);
    CHECK(pay_conn_fails(1, 0, 0, -1, 1000, 1000) == 1);

    /* Send, as before: exactly LEN, and first_bad is not a sender's. */
    CHECK(pay_conn_fails(0, 0, 1, -1, 1000, 1000) == 0);
    CHECK(pay_conn_fails(0, 0, 1, -1,  999, 1000) == 1);
    CHECK(pay_conn_fails(0, 1, 1, 17, 1000, 1000) == 0);

    printf("payverdict: %d checks, %d failure(s)\n", checks, failures);
    return failures != 0;
}
