/*
 * AmiNetXDuo, the mask a static interface carries when its file omits NETMASK.
 *
 * A static interface added at run time reaches nx_ip_interface_attach() with
 * a zero mask when its file has no NETMASK line, and a zero mask makes NetX
 * Duo answer "is this destination on my network?" as yes to everything.  The
 * start-up pass already substitutes /24; this pins the runtime fallback to
 * the same answer so the two paths cannot disagree.
 *
 * SPDX-License-Identifier: MIT
 */

#include "netstack_mask.h"

#include <stdio.h>


static unsigned long h_checks;
static unsigned long h_failures;


static void h_check(int ok, const char *what)
{
    h_checks++;
    if (!ok)
    {
        h_failures++;
        printf("FAIL %s\n", what);
    }
}


static void h_case_omitted_mask_is_twenty_four(void)
{
    /* No NETMASK line: the parser leaves netmask at 0, and the interface
       must come up /24, the same mask the start-up pass substitutes. */
    h_check(ami_ns_static_netmask(0UL) == 0xFFFFFF00UL,
            "an omitted NETMASK becomes 255.255.255.0");
}


static void h_case_a_written_mask_is_kept(void)
{
    /* Every explicit mask is kept byte for byte. */
    h_check(ami_ns_static_netmask(0xFF000000UL) == 0xFF000000UL,
            "/8 is kept");
    h_check(ami_ns_static_netmask(0xFFFF0000UL) == 0xFFFF0000UL,
            "/16 is kept");
    h_check(ami_ns_static_netmask(0xFFFFFF00UL) == 0xFFFFFF00UL,
            "/24 is kept");
    h_check(ami_ns_static_netmask(0xFFFFFFF0UL) == 0xFFFFFFF0UL,
            "/28 is kept");
    h_check(ami_ns_static_netmask(0xFFFFFFFFUL) == 0xFFFFFFFFUL,
            "/32 is kept");
}


int main(void)
{
    h_case_omitted_mask_is_twenty_four();
    h_case_a_written_mask_is_kept();

    printf("%lu checks, %lu failures\n", h_checks, h_failures);

    return (h_failures == 0) ? 0 : 1;
}
