/*
 * AmiNetXDuo, host shim for tests/syncache: ThreadX's port header with ULONG
 * 64 bits wide, the one width tests/perf/host/shim does not give.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef AMINETXDUO_HOST_TX_PORT_ULONG64
#define AMINETXDUO_HOST_TX_PORT_ULONG64

#ifndef AMINETXDUO_HOST_VENDORED_TX_PORT
#error "AMINETXDUO_HOST_VENDORED_TX_PORT must name the tx_port.h to wrap"
#endif

#define LONG    aminetxduo_host_ulong64_LONG
#define ULONG   aminetxduo_host_ulong64_ULONG
#include AMINETXDUO_HOST_VENDORED_TX_PORT
#undef LONG
#undef ULONG

typedef long            LONG;
typedef unsigned long   ULONG;

_Static_assert(sizeof(ULONG) == 8, "this shim is for a 64-bit ULONG");

#endif /* AMINETXDUO_HOST_TX_PORT_ULONG64 */
