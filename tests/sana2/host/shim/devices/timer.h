/*
 * <devices/timer.h> for the sana2 host test: struct timeval only, and named
 * s2_timeval because the host's own <sys/time.h> arrives through the NetX Duo
 * linux port header and gets there first.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef AMINETXDUO_SANA2_TEST_DEVICES_TIMER_H
#define AMINETXDUO_SANA2_TEST_DEVICES_TIMER_H

#include <exec/types.h>
#include <exec/io.h>
#include <sys/time.h>

struct s2_timeval
{
    ULONG tv_secs;
    ULONG tv_micro;
};

/* ami_sana2_offline()'s deadline. */
struct timerequest
{
    struct IORequest  tr_node;
    struct s2_timeval tr_time;
};

#define TIMERNAME       "timer.device"
#define UNIT_MICROHZ    0
#define UNIT_VBLANK     1
#define TR_ADDREQUEST   9

#endif
