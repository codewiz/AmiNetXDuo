/*
 * <proto/timer.h> for the sana2 host tests: ReadEClock(), which the test
 * that needs it defines.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef AMINETXDUO_SANA2_TEST_PROTO_TIMER_H
#define AMINETXDUO_SANA2_TEST_PROTO_TIMER_H

#include <devices/timer.h>

ULONG ReadEClock(struct EClockVal *dest);

#endif
