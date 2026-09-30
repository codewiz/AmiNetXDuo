/*
 * F-036: an IPv6 build without RFC 3542 ancillary data (AMINETXDUO_IPV6 on,
 * AMINETXDUO_CMSG off, a legal combination).  raw.c applies as_Icmp6Filter
 * to every raw ICMPv6 socket whatever AMINETXDUO_CMSG says, and ICMP6_FILTER,
 * the only setter, is not built.  The stub bsd_cmsg_reset() must therefore
 * install the RFC 3542 3.2 default, pass everything, as the built one does;
 * left zero, the socket received nothing but an empty ICMPv6 message.
 *
 * cmsg.c is #included, built as that combination.
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"

#include <stdio.h>
#include <string.h>

#if !defined(AMINETXDUO_IPV6) || defined(AMINETXDUO_CMSG)
#error "this test is the IPV6=ON, CMSG=OFF build"
#endif

static unsigned long h_checks;
static unsigned long h_failures;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        h_checks++;                                                           \
        if (!(cond)) {                                                        \
            h_failures++;                                                     \
            printf("  FAIL %s\n", (what));                                    \
        }                                                                     \
    } while (0)

VOID bsd_bzero(APTR p, ULONG size) { memset(p, 0, size); }
VOID bsd_bcopy(CONST_APTR src, APTR dst, ULONG size) { memcpy(dst, src, size); }

#include "cmsg.c"

/* raw.c:288-297, the test a delivered ICMPv6 message of this type passes. */
static int passes(const AmiSocket *sock, ULONG type)
{
    return (sock->as_Icmp6Filter[type >> 5] & (1UL << (type & 31))) != 0UL;
}

int main(void)
{
    static AmiSocket sock;              /* zeroed, as a new socket's memory is */
    ULONG            type;
    int              all = 1;

    bsd_cmsg_reset(&sock);

    for (type = 0; type < 256; type++)
    {
        if (!passes(&sock, type))
            all = 0;
    }
    CHECK(all, "every ICMPv6 type passes a new raw socket's filter");
    CHECK(passes(&sock, 128) && passes(&sock, 129),
          "echo request and reply among them (ping6)");
    CHECK(sock.as_CmsgSticky.cs_Have == FALSE,
          "and the sticky ancillary state is still cleared");

    printf("icmp6_filter_nocmsg: %lu checks, %lu failures\n",
           h_checks, h_failures);
    return (h_failures != 0) ? 1 : 0;
}
