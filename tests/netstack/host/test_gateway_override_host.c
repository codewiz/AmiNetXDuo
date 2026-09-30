/*
 * F-017: a route command's default gateway against a DHCP reconcile that
 * lands between the command's NetX call and its override.  The put of
 * nx_ip_protection that ends the command's set or clear hands the mutex to a
 * reconcile queued behind it, and the DHCP thread outranks an adopted caller,
 * so the reconcile runs there, while the mode still says AUTO.  The override
 * must leave the live gateway as the command made it.
 *
 * netstack_gateway_apply.c is #included; the NetX gateway calls act on one
 * live gateway word, and h_between() is the DHCP thread getting in.
 *
 * SPDX-License-Identifier: MIT
 */

#include "netstack_internal.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

#define DHCP_GW     0xC0A80101UL        /* 192.168.1.1, the lease's */
#define ROUTE_GW    0xC0A801FEUL        /* 192.168.1.254, the command's */

static AmiNetStack h_ns;
static AmiIfConfig h_ifcfg[AMI_CFG_MAX_ATTACHED];
static ULONG       h_gw;                /* the live default gateway */

/* ---- NetX: one gateway word ---- */

UINT _nx_ip_gateway_address_get(NX_IP *ip, ULONG *addr)
{
    (void)ip;
    *addr = h_gw;
    return NX_SUCCESS;
}

UINT _nxe_ip_gateway_address_get(NX_IP *ip, ULONG *addr)
{
    return _nx_ip_gateway_address_get(ip, addr);
}

UINT _nx_ip_gateway_address_set(NX_IP *ip, ULONG addr)
{
    ip->nx_ip_gateway_interface = &ip->nx_ip_interface[0];
    h_gw = addr;
    return NX_SUCCESS;
}

UINT _nxe_ip_gateway_address_set(NX_IP *ip, ULONG addr)
{
    return _nx_ip_gateway_address_set(ip, addr);
}

UINT _nx_ip_gateway_address_clear(NX_IP *ip)
{
    ip->nx_ip_gateway_interface = NX_NULL;
    h_gw = 0UL;
    return NX_SUCCESS;
}

UINT _nxe_ip_gateway_address_clear(NX_IP *ip)
{
    return _nx_ip_gateway_address_clear(ip);
}

UINT _nx_ip_gateway_interface_address_set(NX_IP *ip, UINT index, ULONG addr)
{
    ip->nx_ip_gateway_interface = &ip->nx_ip_interface[index];
    h_gw = addr;
    return NX_SUCCESS;
}

UINT _nxe_ip_gateway_interface_address_set(NX_IP *ip, UINT index, ULONG addr)
{
    return _nx_ip_gateway_interface_address_set(ip, index, addr);
}

/* ---- the netstack around it ---- */

AmiNetStack *ami_netstack_raw(VOID) { return &h_ns; }
VOID ami_netstack_config_routes_install(AmiNetStack *ns) { (void)ns; }
VOID ami_event(UWORD code, UWORD index, ULONG value)
{ (void)code; (void)index; (void)value; }

#include "netstack_gateway_apply.c"

/* One DHCP interface, bound, its lease naming DHCP_GW. */
static void h_stack(void)
{
    memset(&h_ns, 0, sizeof(h_ns));
    memset(h_ifcfg, 0, sizeof(h_ifcfg));
    h_ns.ns_Config.interfaces = h_ifcfg;    /* grown at run time, a pointer */
    h_ns.ns_IpCreated = TRUE;
    h_ns.ns_IfaceCount = 1;
    h_ns.ns_Iface[0] = (AmiSana2If *)(void *)&h_ns;     /* any non-NULL */
    h_ns.ns_Config.interfaces[0].configured = TRUE;
    h_ns.ns_Config.interfaces[0].iptype = AMI_IPTYPE_DHCP;
    h_ns.ns_Config.interfaces[0].gateway = DHCP_GW;
#ifdef AMINETXDUO_DHCP
    h_ns.ns_DhcpGateway[0] = DHCP_GW;
#endif
    h_ns.ns_Ip.nx_ip_interface[0].nx_interface_valid = 1;
    h_ns.ns_Ip.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    h_ns.ns_GatewayPrimary = AMI_NS_GATEWAY_NO_IFACE;
    h_ns.ns_GatewayMode = (UBYTE)AMI_NS_GATEWAY_AUTO;

    h_gw = 0UL;
    ami_ns_gateway_reconcile(&h_ns, AMI_NS_GATEWAY_NO_IFACE, "DHCP bind");
}

/* The DHCP thread, getting in after the command's NetX call. */
static void h_between(void)
{
    ami_ns_gateway_reconcile(&h_ns, AMI_NS_GATEWAY_NO_IFACE, "DHCP renew");
}

int main(void)
{
    /* The fixture: AUTO picks the lease's gateway. */
    h_stack();
    CHECK(h_gw == DHCP_GW);

    /* AddNetRoute DEFAULTGATEWAY: set, DHCP in between, override. */
    h_stack();
    (VOID)_nx_ip_gateway_address_set(&h_ns.ns_Ip, ROUTE_GW);
    h_between();
    netstack_gateway_override_set(ROUTE_GW);
    CHECK(h_gw == ROUTE_GW);
    CHECK(h_ns.ns_GatewayMode == (UBYTE)AMI_NS_GATEWAY_FIXED);

    /* And it holds against the next DHCP event. */
    h_between();
    CHECK(h_gw == ROUTE_GW);

    /* DeleteNetRoute DEFAULTGATEWAY: clear, DHCP in between, override. The
       lease's default must not come back. */
    h_stack();
    (VOID)_nx_ip_gateway_address_clear(&h_ns.ns_Ip);
    h_between();
    netstack_gateway_override_clear();
    CHECK(h_gw == 0UL);
    CHECK(h_ns.ns_GatewayMode == (UBYTE)AMI_NS_GATEWAY_CLEARED);
    h_between();
    CHECK(h_gw == 0UL);

    /* No DHCP in between: as before. */
    h_stack();
    (VOID)_nx_ip_gateway_address_set(&h_ns.ns_Ip, ROUTE_GW);
    netstack_gateway_override_set(ROUTE_GW);
    CHECK(h_gw == ROUTE_GW);

    printf("RESULT gateway_override checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
