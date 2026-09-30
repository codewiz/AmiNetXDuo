/* bsd_raw_send_packet() with IP_HDRINCL to an IPv6 destination: the caller's
   IPv6 header is translated, not sent as payload behind NetX's (F-061).  The
   IPv4 header path, which an IPv4-mapped destination takes, is unchanged.
   The shipping raw.c is compiled in; NetX and source selection are stubbed. */
#include <stdio.h>
#include <string.h>
#include "bsdsocket_vectors.h"

static UINT        h_sent;
static NXD_ADDRESS h_dest;
static ULONG       h_protocol;
static UINT        h_ttl;
static ULONG       h_tos;
static ULONG       h_length;
static UCHAR      *h_first;
static LONG        h_err;

ULONG netstack_interface_epoch(UWORD index)
{
    (VOID)index;
    return 0;
}

BOOL netstack_ipv4_route(ULONG destination, LONG preferred_index,
                         UWORD *index_out, ULONG *next_hop_out,
                         ULONG *source_address_out)
{
    (VOID)destination;
    (VOID)preferred_index;
    (VOID)next_hop_out;
    (VOID)source_address_out;
    *index_out = 0;
    return TRUE;
}

BsdSourceKind bsd_source_select(const AmiSocket *sock, const NXD_ADDRESS *dest,
                                ULONG scope, UINT *index)
{
    (VOID)sock;
    (VOID)scope;
    *index = 0;
    return (dest->nxd_ip_version == NX_IP_VERSION_V6) ? BSD_SOURCE_INDEX
                                                       : BSD_SOURCE_ROUTE;
}

LONG bsd_cmsg_source_index(NX_IP *ip, const BsdCmsgSource *src, BOOL v6)
{
    (VOID)ip;
    (VOID)src;
    (VOID)v6;
    return -1;
}

LONG bsd_fail(struct AmiSocketBase *base, LONG code)
{
    (VOID)base;
    h_err = code;
    return -1;
}

UINT _txe_mutex_get(TX_MUTEX *mutex_ptr, ULONG wait_option)
{
    (VOID)mutex_ptr;
    (VOID)wait_option;
    return TX_SUCCESS;
}

UINT _txe_mutex_put(TX_MUTEX *mutex_ptr)
{
    (VOID)mutex_ptr;
    return TX_SUCCESS;
}

UINT _nxe_packet_release(NX_PACKET **packet_ptr_ptr)
{
    (VOID)packet_ptr_ptr;
    return NX_SUCCESS;
}

UINT _nxde_ip_raw_packet_source_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                                     NXD_ADDRESS *destination_ip,
                                     UINT address_index, ULONG protocol,
                                     UINT ttl, ULONG tos)
{
    (VOID)ip_ptr;
    (VOID)address_index;
    h_sent++;
    h_dest = *destination_ip;
    h_protocol = protocol;
    h_ttl = ttl;
    h_tos = tos;
    h_length = packet_ptr->nx_packet_length;
    h_first = packet_ptr->nx_packet_prepend_ptr;
    return NX_SUCCESS;
}

UINT _nxde_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET **packet_ptr_ptr,
                              NXD_ADDRESS *destination_ip, ULONG protocol,
                              UINT ttl, ULONG tos)
{
    return _nxde_ip_raw_packet_source_send(ip_ptr, *packet_ptr_ptr,
                                           destination_ip, 0, protocol, ttl,
                                           tos);
}

USHORT _nx_ip_checksum_compute(NX_PACKET *packet_ptr, ULONG protocol,
                               UINT data_length, ULONG *_src_ip_addr,
                               ULONG *_dest_ip_addr)
{
    (VOID)packet_ptr;
    (VOID)protocol;
    (VOID)data_length;
    (VOID)_src_ip_addr;
    (VOID)_dest_ip_addr;
    return 0;
}

BOOL netstack_ipv6_source_find(const ULONG dest[4], LONG interface_index,
                               ULONG addr_out[4], UINT *address_index_out)
{
    (VOID)dest;
    (VOID)interface_index;
    (VOID)addr_out;
    (VOID)address_index_out;
    return FALSE;
}

LONG bsd_errno_from_nx(UINT status)
{
    return (LONG)status;
}

/* Unused raw.c and mcast.c entry points disappear with section GC. */
#include "../../../src/bsdsocket/mcast.c"
#include "../../../src/bsdsocket/raw.c"

static unsigned checks;
static unsigned failures;

static void check(int condition, const char *name)
{
    checks++;
    if (!condition)
    {
        failures++;
        printf("FAIL %s\n", name);
    }
}

static struct AmiSocketBase h_base;
static NX_IP                h_ip;
static NX_PACKET            h_packet;
static UCHAR                h_data[96];

static LONG send_len(AmiSocket *sock, const NXD_ADDRESS *addr, ULONG len)
{
    memset(&h_packet, 0, sizeof h_packet);
    h_packet.nx_packet_prepend_ptr = h_data;
    h_packet.nx_packet_append_ptr = h_data + len;
    h_packet.nx_packet_length = len;
    h_sent = 0;
    h_err = 0;
    memset(&h_dest, 0, sizeof h_dest);
    return bsd_raw_send_packet(&h_base, sock, &h_packet, addr, 0UL, NULL);
}

/* 2001:db8::n */
static void h_v6(NXD_ADDRESS *a, ULONG n)
{
    memset(a, 0, sizeof *a);
    a->nxd_ip_version = NX_IP_VERSION_V6;
    a->nxd_ip_address.v6[0] = 0x20010db8UL;
    a->nxd_ip_address.v6[3] = n;
}

/* A fixed IPv6 header in h_data: traffic class 0xA5, next header 253, hop
   limit 9, destination 2001:db8::2; then 8 bytes of payload. */
static void h_header6(void)
{
    memset(h_data, 0, sizeof h_data);
    h_data[0] = 0x6A;                   /* version 6, traffic class high 0xA */
    h_data[1] = 0x50;                   /* traffic class low 0x5 */
    h_data[5] = 8;                      /* payload length */
    h_data[6] = 253;
    h_data[7] = 9;
    h_data[24] = 0x20; h_data[25] = 0x01; h_data[26] = 0x0d; h_data[27] = 0xb8;
    h_data[39] = 2;
    h_data[40] = 0xEE;
}

int main(void)
{
    AmiSocket   sock;
    NXD_ADDRESS to;

    memset(&h_base, 0, sizeof h_base);
    memset(&h_ip, 0, sizeof h_ip);
    h_base.sb_StackRefs = 1;
    h_base.sb_StackIp = &h_ip;

    memset(&sock, 0, sizeof sock);
    sock.as_Owner = &h_base;
    sock.as_Flags = ASF_INET6;
    sock.as_Protocol = 17;
    sock.as_Ttl = 64;
    sock.as_McastIf = -1;

    /* Without IP_HDRINCL nothing is taken from the data. */
    h_header6();
    h_v6(&to, 1);
    check(send_len(&sock, &to, 48) == 0 && h_sent == 1, "a plain IPv6 send");
    check(h_length == 48 && h_first == h_data && h_protocol == 17 &&
          h_ttl == 64 && h_dest.nxd_ip_address.v6[3] == 1,
          "sends the data whole, with the socket's protocol and hops");

    /* IP_HDRINCL: the header is the header. */
    sock.as_HdrIncl = 1;
    h_header6();
    check(send_len(&sock, &to, 48) == 0 && h_sent == 1, "an IP_HDRINCL IPv6 send");
    check(h_length == 8 && h_first == h_data + 40 && h_first[0] == 0xEE,
          "the header is not sent as payload");
    check(h_protocol == 253, "next header is the protocol");
    check(h_ttl == 9, "hop limit is the header's");
    check(h_tos == 0xA5, "traffic class is the header's");
    check(h_dest.nxd_ip_version == NX_IP_VERSION_V6 &&
          h_dest.nxd_ip_address.v6[0] == 0x20010db8UL &&
          h_dest.nxd_ip_address.v6[3] == 2,
          "and the destination is the header's");

    h_header6();
    check(send_len(&sock, &to, 39) == -1 && h_err == AMI_EINVAL && h_sent == 0,
          "a header shorter than 40 bytes is EINVAL");
    h_header6();
    h_data[0] = 0x45;
    check(send_len(&sock, &to, 48) == -1 && h_err == AMI_EINVAL && h_sent == 0,
          "an IPv4 header to an IPv6 destination is EINVAL");

    /* An IPv4 destination (as an IPv4-mapped one arrives here, normalised)
       still takes the IPv4 header. */
    memset(h_data, 0, sizeof h_data);
    h_data[0] = 0x45;
    h_data[8] = 3;
    h_data[9] = 253;
    h_data[16] = 192; h_data[17] = 0; h_data[18] = 2; h_data[19] = 7;
    memset(&to, 0, sizeof to);
    to.nxd_ip_version = NX_IP_VERSION_V4;
    to.nxd_ip_address.v4 = 0xc0000207UL;
    check(send_len(&sock, &to, 28) == 0 && h_sent == 1 && h_length == 8 &&
          h_ttl == 3 && h_protocol == 253 &&
          h_dest.nxd_ip_version == NX_IP_VERSION_V4 &&
          h_dest.nxd_ip_address.v4 == 0xc0000207UL,
          "an IPv4 destination still translates the IPv4 header");

    printf("raw hdrincl6: %u checks, %u failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
