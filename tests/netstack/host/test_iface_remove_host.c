/*
 * RemoveNetInterface FORCE on a device that never gives its reads back.
 *
 * On a PiStorm32 A1200 `RemoveNetInterface wifipi FORCE` stopped every
 * interface until a power cycle.  The removal ran the device's stop inside
 * NX_LINK_DISABLE, so inside nx_ip_protection, the IP mutex every interface's
 * traffic takes, and with ami_ns_lock held over the whole removal; then it
 * refused, the reads still held, without resetting a socket.  What this file
 * holds the removal to: the stop of the device waits with neither lock held,
 * another interface can be used while it waits, the slot being removed cannot
 * be claimed or removed twice meanwhile, and the removal completes: detached,
 * which resets the interface's TCP sockets, and retained.
 *
 * Also: which TCP states count as "connections open".
 *
 * netstack.c is compiled whole; see tests/netstack/host/netstack_host_env.h.
 *
 * SPDX-License-Identifier: MIT
 */

#include "netstack_host_env.h"

#include "aminetxduo/netstack.h"
#include "aminetxduo/netstatus.h"

#include <stdio.h>
#include <string.h>

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

static void h_iface(AmiIfConfig *cfg, const char *name, const char *device,
                    ULONG address)
{
    memset(cfg, 0, sizeof(*cfg));
    strcpy(cfg->name, name);
    strcpy(cfg->device, device);
    cfg->iptype     = AMI_IPTYPE_STATIC;
    cfg->address    = address;
    cfg->netmask    = 0xFFFFFF00UL;
    cfg->up         = TRUE;
    cfg->configured = TRUE;
}

/* The loopback stack, "eth" in slot 0 and "wifi" in slot 1. */
static BOOL h_up_two(void)
{
    AmiIfConfig cfg;
    UWORD       eth = 99;
    UWORD       wifi = 99;

    nsh_reset();
    if (netstack_startup_loopback() != AMI_NET_OK)
        return FALSE;

    h_iface(&cfg, "eth", "a2065.device", 0xC0A80105UL);
    if (netstack_interface_start(&cfg, &eth) != AMI_NET_OK || eth != 0)
        return FALSE;

    h_iface(&cfg, "wifi", "wifipi.device", 0xC0A80205UL);
    return (netstack_interface_start(&cfg, &wifi) == AMI_NET_OK &&
            wifi == 1) ? TRUE : FALSE;
}

static void h_teardown(void)
{
    UWORD i;

    for (i = 0; i < (UWORD)NSH_SANA2_IFACES; i++)
    {
        nsh.sana2[i].held        = 0;
        nsh.sana2[i].keeps_reads = FALSE;
    }
    nsh.sana2_orphaned = FALSE;
    nsh.during_stop    = NULL;

    netstack_shutdown();
    netstack_shutdown();
}

/* ---------------------------------------------- what another task does */

static ULONG h_other_would_block;
static LONG  h_other_claim;
static LONG  h_same_claim;
static LONG  h_second_remove;

/*
 * Another Task while the stop waits.  A claim takes ami_ns_lock, and with it
 * held by the removal that Task would sleep in ObtainSemaphore() for as long
 * as the device keeps its reads.  The stubs do not sleep, so the call is made
 * only when it would not have blocked.
 */
static VOID h_meanwhile(VOID)
{
    UWORD index;

    if (nsh.sem_depth != 0)
    {
        h_other_would_block++;
        return;
    }

    h_other_claim = netstack_interface_claim("eth", &index);
    if (h_other_claim == AMI_NET_OK)
        netstack_interface_release(index);

    h_same_claim = netstack_interface_claim("wifi", &index);
    if (h_same_claim == AMI_NET_OK)
        netstack_interface_release(index);

    h_second_remove = netstack_interface_remove_named("wifi", TRUE);
}

/* ------------------------------------------------------------- the cases */

static void t_force_on_a_device_that_keeps_its_reads(void)
{
    AmiNetStack *ns;
    NshSana2If  *wifi;
    UWORD        index;
    ULONG        detaches;
    LONG         rc;

    printf("remove: FORCE on a device that never gives its reads back\n");

    CHECK(h_up_two(), "eth in slot 0, wifi in slot 1");
    ns   = netstack_get();
    wifi = (ns != NULL) ? nsh_sana2_of(ns->ns_Iface[1]) : NULL;
    CHECK(wifi != NULL, "wifi is a modelled device");
    if (wifi == NULL)
    {
        h_teardown();
        return;
    }

    wifi->keeps_reads   = TRUE;
    nsh.during_stop     = h_meanwhile;
    h_other_would_block = 0;
    h_other_claim       = AMI_NET_ERR_STATE;
    h_same_claim        = AMI_NET_ERR_STATE;
    h_second_remove     = AMI_NET_ERR_STATE;
    detaches            = nsh.iface_detaches;

    rc = netstack_interface_remove_named("wifi", TRUE);

    CHECK(nsh.device_waits == 1, "the stop waited on the device once");
    CHECK(nsh.waits_in_ip_mutex == 0,
          "not inside nx_ip_protection, which every interface's traffic takes");
    CHECK(nsh.waits_under_ns_lock == 0, "and not under ami_ns_lock");
    CHECK(h_other_would_block == 0,
          "another task was not held up behind the removal");
    CHECK(h_other_claim == AMI_NET_OK,
          "it claimed eth while the device was being stopped");
    CHECK(h_same_claim == AMI_NET_ERR_BUSY,
          "a claim on the interface being removed was refused");
    CHECK(h_second_remove == AMI_NET_ERR_BUSY,
          "and so was a second removal of it");

    CHECK(rc == AMI_NET_ERR_RETAINED,
          "the removal completes, and says the device kept requests");
    CHECK(nsh.iface_detaches == detaches + 1,
          "wifi left NetX Duo, which resets its TCP sockets");
    CHECK(ns->ns_Iface[1] == NULL && ns->ns_IfaceClaims[1] == 0,
          "and its slot is empty and unclaimed");
    CHECK(wifi->state == NSH_IF_RETAINED,
          "the device's interface is retained, not closed under its reads");
    CHECK(nsh.sem_depth == 0, "every lock was given back");

    CHECK(ns->ns_Iface[0] != NULL, "eth is still attached");
    CHECK(netstack_interface_claim("eth", &index) == AMI_NET_OK && index == 0,
          "and can be claimed");
    netstack_interface_release(0);

    h_teardown();
}

/* A device that answers: the same three steps, and a clean close. */
static void t_remove_a_device_that_answers(void)
{
    AmiNetStack *ns;
    NshSana2If  *wifi;

    printf("remove: a device that gives everything back\n");

    CHECK(h_up_two(), "eth in slot 0, wifi in slot 1");
    ns   = netstack_get();
    wifi = (ns != NULL) ? nsh_sana2_of(ns->ns_Iface[1]) : NULL;

    CHECK(netstack_interface_remove(1, FALSE) == AMI_NET_OK, "removed");
    CHECK(nsh.device_waits == 0, "nothing was waited out");
    CHECK(wifi != NULL && wifi->state == NSH_IF_FREE &&
          wifi->device_closes == 1, "closed once");
    CHECK(nsh.sem_depth == 0, "every lock was given back");

    h_teardown();
}

/* ------------------------------------------------- connections open */

static NX_TCP_SOCKET h_sock;

static void h_sock_on(AmiNetStack *ns, UWORD index, UINT state)
{
    memset(&h_sock, 0, sizeof(h_sock));
    h_sock.nx_tcp_socket_state             = state;
    h_sock.nx_tcp_socket_connect_interface = &ns->ns_Ip.nx_ip_interface[index];
    h_sock.nx_tcp_socket_created_next      = &h_sock;
    h_sock.nx_tcp_socket_created_previous  = &h_sock;
    ns->ns_Ip.nx_ip_tcp_created_sockets_ptr   = &h_sock;
    ns->ns_Ip.nx_ip_tcp_created_sockets_count = 1;
}

static void h_sock_off(AmiNetStack *ns)
{
    ns->ns_Ip.nx_ip_tcp_created_sockets_ptr   = NX_NULL;
    ns->ns_Ip.nx_ip_tcp_created_sockets_count = 0;
}

static void h_users_case(UINT state, BOOL counts, const char *what)
{
    AmiNetStack *ns;
    LONG         rc;

    CHECK(h_up_two(), "eth in slot 0, wifi in slot 1");
    ns = netstack_get();
    if (ns == NULL)
        return;

    h_sock_on(ns, 1, state);
    rc = netstack_interface_remove(1, FALSE);
    CHECK(counts ? (rc == AMI_NET_ERR_BUSY) : (rc == AMI_NET_OK), what);
    h_sock_off(ns);

    if (counts)
        CHECK(netstack_interface_remove(1, TRUE) == AMI_NET_OK,
              "FORCE removes it anyway");

    h_teardown();
}

static void t_connections_open(void)
{
    printf("remove: which TCP states are connections open\n");

    h_users_case(NX_TCP_ESTABLISHED, TRUE,
                 "ESTABLISHED refuses a removal without FORCE");
    h_users_case(NX_TCP_CLOSE_WAIT, TRUE,
                 "CLOSE_WAIT refuses it: the peer is done, the program is not");
    h_users_case(NX_TCP_TIMED_WAIT, FALSE,
                 "TIME_WAIT does not: both ends have closed");
    h_users_case(NX_TCP_LISTEN_STATE, FALSE,
                 "LISTEN does not: a listener is bound to no interface");
}

int main(void)
{
    t_force_on_a_device_that_keeps_its_reads();
    t_remove_a_device_that_answers();
    t_connections_open();

    printf("%lu checks, %lu failures, %s\n", h_checks, h_failures,
           (h_failures == 0) ? "PASS" : "FAIL");

    return (h_failures == 0) ? 0 : 1;
}
