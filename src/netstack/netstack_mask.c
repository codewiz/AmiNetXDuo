/*
 * AmiNetXDuo, the mask a static interface carries when its file omits NETMASK.
 *
 * SPDX-License-Identifier: MIT
 */

#include "netstack_mask.h"

ULONG ami_ns_static_netmask(ULONG netmask)
{
    return (netmask != 0UL) ? netmask : 0xFFFFFF00UL;
}
