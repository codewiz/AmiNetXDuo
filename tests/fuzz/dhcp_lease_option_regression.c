/*
 * AmiNetXDuo, host regression for the requested DHCP lease (F-030).
 *
 * The DHCP client always sent one option 51 in DISCOVER and in REQUEST before
 * it is bound, fixed at the infinite lease.  nx_dhcp_interface_request_lease()
 * sets the value of that same option per interface; 0 keeps infinite.  This
 * builds real messages with _nx_dhcp_send_request_internal() and reads the
 * bytes handed to UDP: exactly one option 51, four bytes long, carrying the
 * requested lease, or 0xffffffff when none was requested.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NX_THREAD_EXTENSION_PTR_GET(a, b, c)    { (a) = NX_NULL; }
#define NX_TIMER_EXTENSION_PTR_GET(a, b, c)     { (a) = NX_NULL; }

#include "nx_api.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "nxd_dhcp_client.c"
#pragma GCC diagnostic pop

UINT _nx_arp_probe_send(NX_IP *ip_ptr, UINT interface_index, ULONG probe_address)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(probe_address);
    return NX_SUCCESS;
}

static int checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++;                  \
    printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__);            \
    printf("\n"); } } while (0)

/* The wire, as the client hands it to UDP. */
static unsigned char sent[2048];
static ULONG         sent_len;
static int           sent_count;

UINT _nx_udp_socket_interface_send(NX_UDP_SOCKET *socket_ptr, NX_PACKET *packet_ptr,
                                   ULONG ip_address, UINT port, UINT address_index)
{
    ULONG n = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

    NX_PARAMETER_NOT_USED(socket_ptr);
    NX_PARAMETER_NOT_USED(ip_address);
    NX_PARAMETER_NOT_USED(port);
    NX_PARAMETER_NOT_USED(address_index);

    if (n > sizeof(sent))
        n = sizeof(sent);
    memcpy(sent, packet_ptr -> nx_packet_prepend_ptr, n);
    sent_len = n;
    sent_count++;
    nx_packet_release(packet_ptr);
    return NX_SUCCESS;
}

/* DISCOVER and REQUEST before BOUND go out with a zero source address,
   straight to the link driver as a broadcast; the IP and UDP headers are in
   front of the DHCP message. */
static VOID capture_driver(NX_IP_DRIVER *req)
{
    NX_PACKET *packet_ptr = req -> nx_ip_driver_packet;
    ULONG      n;

    req -> nx_ip_driver_status = NX_SUCCESS;
    if (req -> nx_ip_driver_command != NX_LINK_PACKET_BROADCAST || packet_ptr == NX_NULL)
        return;

    n = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);
    n = (n > 28) ? n - 28 : 0;                  /* past IPv4 (20) and UDP (8) */
    if (n > sizeof(sent))
        n = sizeof(sent);
    memcpy(sent, packet_ptr -> nx_packet_prepend_ptr + 28, n);
    sent_len = n;
    sent_count++;
    nx_packet_transmit_release(packet_ptr);
}

static NX_DHCP        g_dhcp;
static NX_IP          g_ip;
static NX_PACKET_POOL g_pool;
static ULONG          g_pool_area[(8 * (1536 + sizeof(NX_PACKET) + 64)) / sizeof(ULONG)];

static NX_DHCP_INTERFACE_RECORD *setup(void)
{
    NX_DHCP_INTERFACE_RECORD *rec;

    memset(&g_dhcp, 0, sizeof(g_dhcp));
    memset(&g_ip, 0, sizeof(g_ip));
    memset(&g_pool, 0, sizeof(g_pool));

    g_ip.nx_ip_id = NX_IP_ID;
    g_ip.nx_ip_interface[0].nx_interface_valid   = NX_TRUE;
    g_ip.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    g_ip.nx_ip_interface[0].nx_interface_physical_address_msw = 0x0002;
    g_ip.nx_ip_interface[0].nx_interface_physical_address_lsw = 0x03040506;
    g_ip.nx_ip_interface[0].nx_interface_ip_mtu_size = 1500;
    g_ip.nx_ip_interface[0].nx_interface_link_driver_entry = capture_driver;

    if (_nx_packet_pool_create(&g_pool, "dhcp", 1536, g_pool_area, sizeof(g_pool_area))
            != NX_SUCCESS)
    {
        printf("FAIL the packet pool\n");
        exit(1);
    }

    g_dhcp.nx_dhcp_ip_ptr          = &g_ip;
    g_dhcp.nx_dhcp_packet_pool_ptr = &g_pool;

    rec = &g_dhcp.nx_dhcp_interface_record[0];
    rec->nx_dhcp_record_valid    = NX_TRUE;
    rec->nx_dhcp_interface_index = 0;
    rec->nx_dhcp_state           = NX_DHCP_STATE_INIT;
    rec->nx_dhcp_ip_address      = NX_BOOTP_NO_ADDRESS;
    rec->nx_dhcp_server_ip       = NX_BOOTP_NO_ADDRESS;
    return rec;
}

/* Option 51 in the last message sent: how many, the length of the last, its value. */
static void lease_options(int *count, unsigned *length, unsigned long *value)
{
    ULONG i = NX_BOOTP_OFFSET_OPTIONS;              /* the first option, after the magic cookie */

    *count = 0;
    *length = 0;
    *value = 0;
    while (i < sent_len)
    {
        unsigned code = sent[i];

        if (code == 0)                              /* pad */
        {
            i++;
            continue;
        }
        if (code == 255 || i + 1 >= sent_len)       /* end */
            break;
        if (code == NX_DHCP_OPTION_DHCP_LEASE)
        {
            (*count)++;
            *length = sent[i + 1];
            if (*length == 4 && i + 6 <= sent_len)
                *value = ((unsigned long)sent[i + 2] << 24) | ((unsigned long)sent[i + 3] << 16) |
                         ((unsigned long)sent[i + 4] << 8)  |  (unsigned long)sent[i + 5];
        }
        i += 2u + sent[i + 1];
    }
}

static void expect(NX_DHCP_INTERFACE_RECORD *rec, UINT type, unsigned long want, const char *what)
{
    int           count;
    unsigned      length;
    unsigned long value;
    int           before = sent_count;

    {
        UINT status = _nx_dhcp_send_request_internal(&g_dhcp, rec, type);
        CHECK(status == NX_SUCCESS, "%s: sent (status 0x%x)", what, status);
    }
    CHECK(sent_count == before + 1, "%s: one message on the wire", what);
    lease_options(&count, &length, &value);
    CHECK(count == 1, "%s: %d option 51, want exactly one", what, count);
    CHECK(length == 4, "%s: option 51 length %u, want 4", what, length);
    CHECK(value == want, "%s: lease %lu, want %lu", what, value, want);
}

int main(void)
{
    NX_DHCP_INTERFACE_RECORD *rec;

    /* Nothing requested: the infinite lease, as before. */
    rec = setup();
    expect(rec, NX_DHCP_TYPE_DHCPDISCOVER, 0xFFFFFFFFUL, "default DISCOVER");
    expect(rec, NX_DHCP_TYPE_DHCPREQUEST,  0xFFFFFFFFUL, "default REQUEST");

    /* A requested lease replaces the value, not the option. */
    CHECK(_nx_dhcp_interface_request_lease(&g_dhcp, 0, 3600UL) == NX_SUCCESS, "the setter accepts 3600");
    expect(rec, NX_DHCP_TYPE_DHCPDISCOVER, 3600UL, "requested DISCOVER");
    expect(rec, NX_DHCP_TYPE_DHCPREQUEST,  3600UL, "requested REQUEST");

    /* It survives the reinitialise a NAK or an expiry does. */
    _nx_dhcp_interface_reinitialize(&g_dhcp, 0);
    rec->nx_dhcp_state = NX_DHCP_STATE_INIT;
    expect(rec, NX_DHCP_TYPE_DHCPDISCOVER, 3600UL, "requested DISCOVER after reinitialise");

    /* 0 goes back to infinite. */
    CHECK(_nx_dhcp_interface_request_lease(&g_dhcp, 0, 0UL) == NX_SUCCESS, "the setter accepts 0");
    expect(rec, NX_DHCP_TYPE_DHCPDISCOVER, 0xFFFFFFFFUL, "DISCOVER after 0");

    /* An interface with no record is refused, and nothing changes. */
    CHECK(_nx_dhcp_interface_request_lease(&g_dhcp, 1, 60UL) != NX_SUCCESS,
          "an interface DHCP was not enabled on is refused");

    printf("RESULT dhcp_lease_option_regression checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
