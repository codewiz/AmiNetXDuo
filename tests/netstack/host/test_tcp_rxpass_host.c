/*
 * AmiNetXDuo, the receive pass: what a burst leaves below the acknowledgment
 * threshold is acknowledged when the pass that took it in ends, not a round
 * trip later.  Against the real data_check and the real pass functions
 * (nx_tcp_receive_pass_begin.c, nx_tcp_receive_pass_complete.c).
 *
 * The shape is the one an A3000 with an X-Surf 100 showed on a 25 ms path:
 * the receive layer hands TCP runs of at most 16 segments, the threshold
 * ramps to 16 segments (the step of a 46720-byte cap), and a 32-segment
 * window that arrives as 16 + 14 or 16 + 2 left the tail unacknowledged
 * until the next burst, which the sender could not send until it was.
 *
 * SPDX-License-Identifier: MIT
 */

#include "nx_api.h"
#include "nx_tcp.h"
#include "nx_packet.h"
#include "nx_ip.h"

#include <stdio.h>
#include <string.h>

static ULONG h_now = 1000;

ULONG _tx_time_get(VOID)
{
    return h_now;
}

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

TX_THREAD *_tx_thread_current_ptr;

ULONG _nx_tcp_fast_timer_rate;
ULONG _nx_tcp_ack_timer_rate;
ULONG _nx_tcp_transmit_timer_rate;
ULONG _nx_tcp_2MSL_timer_rate;

UINT _nx_tcp_mss_option_get(UCHAR *option_ptr, ULONG option_area_size, ULONG *mss)
{
    (void)option_ptr; (void)option_area_size; (void)mss;
    return NX_TRUE;
}

VOID _nx_tcp_packet_send_rst(NX_TCP_SOCKET *socket_ptr, NX_TCP_HEADER *header_ptr)
{
    (void)socket_ptr; (void)header_ptr;
}

VOID _nx_tcp_sack_option_get(NX_TCP_SOCKET *socket_ptr, UCHAR *option_ptr,
                             ULONG option_area_size)
{
    (void)socket_ptr; (void)option_ptr; (void)option_area_size;
}

VOID _nx_tcp_socket_connection_reset(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
}

UINT _nx_tcp_socket_state_ack_check(NX_TCP_SOCKET *socket_ptr,
                                    NX_TCP_HEADER *header_ptr)
{
    (void)socket_ptr; (void)header_ptr;
    return NX_TRUE;
}

VOID _nx_tcp_socket_state_closing(NX_TCP_SOCKET *socket_ptr,
                                  NX_TCP_HEADER *header_ptr)
{
    (void)socket_ptr; (void)header_ptr;
}

VOID _nx_tcp_socket_state_established(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
}

VOID _nx_tcp_socket_state_fin_wait1(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
}

VOID _nx_tcp_socket_state_fin_wait2(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
}

VOID _nx_tcp_socket_state_last_ack(NX_TCP_SOCKET *socket_ptr,
                                   NX_TCP_HEADER *header_ptr)
{
    (void)socket_ptr; (void)header_ptr;
}

VOID _nx_tcp_socket_state_syn_received(NX_TCP_SOCKET *socket_ptr,
                                       NX_TCP_HEADER *header_ptr)
{
    (void)socket_ptr; (void)header_ptr;
}

VOID _nx_tcp_socket_state_syn_sent(NX_TCP_SOCKET *socket_ptr,
                                   NX_TCP_HEADER *header_ptr,
                                   NX_PACKET *packet_ptr)
{
    (void)socket_ptr; (void)header_ptr; (void)packet_ptr;
}

VOID _nx_tcp_socket_state_transmit_check(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
}

UINT _tx_mutex_get(TX_MUTEX *mutex_ptr, ULONG wait_option)
{
    (void)mutex_ptr; (void)wait_option;
    return TX_SUCCESS;
}

UINT _tx_mutex_put(TX_MUTEX *mutex_ptr)
{
    (void)mutex_ptr;
    return TX_SUCCESS;
}

UINT _tx_thread_interrupt_disable(void)
{
    return 0;
}

VOID _tx_thread_interrupt_restore(UINT previous_posture)
{
    (void)previous_posture;
}

UINT _tx_thread_preemption_change(TX_THREAD *thread_ptr, UINT new_threshold,
                                  UINT *old_threshold)
{
    (void)thread_ptr; (void)new_threshold;
    if (old_threshold)
    {
        *old_threshold = 0;
    }
    return TX_SUCCESS;
}

UINT _tx_thread_sleep(ULONG timer_ticks)
{
    (void)timer_ticks;
    printf("FAIL NX_ASSERT fired\n");
    h_failures++;
    return TX_SUCCESS;
}

VOID _nx_tcp_socket_thread_resume(TX_THREAD **suspension_list_head, UINT status)
{
    (void)suspension_list_head; (void)status;
}


UINT _nx_packet_release(NX_PACKET *packet_ptr)
{
    (void)packet_ptr;
    return NX_SUCCESS;
}

/* The acknowledgment the stack sends, as the real path records it: the
   sequence acknowledged and the window put on the wire.  A failed
   allocation sends nothing and records nothing. */
static NX_TCP_SOCKET *h_ack_sock;
static UINT           h_acks;
static UINT           h_ack_attempts;
static UINT           h_alloc_fails;

VOID _nx_tcp_packet_send_ack(NX_TCP_SOCKET *socket_ptr, ULONG tx_sequence)
{
    (void)tx_sequence;

    h_ack_attempts++;
    if (h_alloc_fails)
    {
        return;
    }
    h_acks++;
    h_ack_sock = socket_ptr;
    socket_ptr -> nx_tcp_socket_rx_sequence_acked = socket_ptr -> nx_tcp_socket_rx_sequence;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent = NX_TCP_RX_WINDOW_ADVERTISED(socket_ptr);
}

#define H_MSS               1460UL
#define H_BUFFER            (64UL * H_MSS)          /* 93440, as settled */
#define H_CAP               (32UL * H_MSS)          /* 46720 */
#define H_LIMIT             (16UL * H_MSS)          /* the ramp's limit */
#define H_ISN_RX            0x20000000UL

/* The step of a 46720-byte cap: what the ramp is limited to. */
ULONG _nx_tcp_socket_window_update_step(NX_TCP_SOCKET *socket_ptr)
{
    (void)socket_ptr;
    return H_LIMIT;
}

#define H_MAX_SEG           512
#define H_BUF               64

static NX_IP          h_ip;
static NX_INTERFACE   h_iface;
static NX_TCP_SOCKET  h_a;
static NX_TCP_SOCKET  h_b;
static NX_PACKET_POOL h_pool;
static NX_PACKET      h_pkt[H_MAX_SEG];
static UCHAR          h_pkt_buf[H_MAX_SEG][H_BUF];
static UINT           h_pkt_next;

static void h_socket(NX_TCP_SOCKET *s, UINT port)
{
    _nx_tcp_socket_create(&h_ip, s, "host rx pass", NX_IP_NORMAL,
                          NX_FRAGMENT_OKAY, 0x80, H_BUFFER, NX_NULL, NX_NULL);

    s -> nx_tcp_socket_bound_next   = s;
    s -> nx_tcp_socket_client_type  = NX_TRUE;
    s -> nx_tcp_socket_state        = NX_TCP_ESTABLISHED;
    s -> nx_tcp_socket_port         = port;
    s -> nx_tcp_socket_connect_port = 80;
    s -> nx_tcp_socket_connect_ip.nxd_ip_version    = NX_IP_VERSION_V4;
    s -> nx_tcp_socket_connect_ip.nxd_ip_address.v4 = 0xC0A80101UL;
    s -> nx_tcp_socket_connect_interface = &h_iface;
    s -> nx_tcp_socket_connect_mss  = H_MSS;
    s -> nx_tcp_socket_connect_mss2 = H_MSS * H_MSS;

    s -> nx_tcp_socket_rx_sequence         = H_ISN_RX;
    s -> nx_tcp_socket_rx_sequence_acked   = H_ISN_RX;
    s -> nx_tcp_socket_rx_window_default   = H_BUFFER;
    s -> nx_tcp_socket_rx_window_current   = H_BUFFER;
    s -> nx_tcp_socket_rx_window_cap       = H_CAP;
    s -> nx_tcp_socket_rx_window_last_sent = H_CAP;

    /* The ramp in steady state: at its limit. */
    s -> nx_tcp_socket_ack_n_packet_counter = H_LIMIT;

    s -> nx_tcp_socket_receive_queue_head  = NX_NULL;
    s -> nx_tcp_socket_receive_queue_tail  = NX_NULL;
    s -> nx_tcp_socket_receive_queue_count = 0;
    s -> nx_tcp_socket_receive_suspension_list = NX_NULL;
    s -> nx_tcp_receive_callback = NX_NULL;
#ifdef NX_ENABLE_LOW_WATERMARK
    s -> nx_tcp_socket_receive_queue_maximum = H_MAX_SEG;
#endif
}

static void h_fixture(void)
{
    memset(&h_ip, 0, sizeof(h_ip));
    memset(&h_iface, 0, sizeof(h_iface));
    memset(&h_pool, 0, sizeof(h_pool));
    h_pool.nx_packet_pool_total     = H_MAX_SEG;
    h_pool.nx_packet_pool_available = H_MAX_SEG;
    h_iface.nx_interface_ip_address = 0xC0A80102UL;

    h_now          = 1000;
    h_pkt_next     = 0;
    h_acks         = 0;
    h_ack_attempts = 0;
    h_alloc_fails  = 0;
    h_ack_sock     = NX_NULL;

    h_socket(&h_a, 40000);
    h_socket(&h_b, 40001);
}

/* The application has read everything: the buffer is free again. */
static void h_read_all(NX_TCP_SOCKET *s)
{
    s -> nx_tcp_socket_receive_queue_head  = NX_NULL;
    s -> nx_tcp_socket_receive_queue_tail  = NX_NULL;
    s -> nx_tcp_socket_receive_queue_count = 0;
    s -> nx_tcp_socket_rx_window_current   = H_BUFFER;
}

/* One run of `segs` full-sized segments, as the receive layer hands it up:
   a single packet, at the next sequence or `ahead` bytes beyond it. */
static void h_run_at(NX_TCP_SOCKET *s, ULONG segs, ULONG ahead)
{
    NX_PACKET     *p;
    NX_TCP_HEADER *hdr;
    ULONG          bytes = segs * H_MSS;

    if (h_pkt_next >= H_MAX_SEG)
    {
        printf("FAIL out of test packets\n");
        h_failures++;
        return;
    }

    p = &h_pkt[h_pkt_next];
    memset(p, 0, sizeof(*p));
    p -> nx_packet_data_start  = h_pkt_buf[h_pkt_next];
    p -> nx_packet_data_end    = h_pkt_buf[h_pkt_next] + H_BUF;
    p -> nx_packet_prepend_ptr = h_pkt_buf[h_pkt_next];
    p -> nx_packet_append_ptr  = h_pkt_buf[h_pkt_next] + sizeof(NX_TCP_HEADER);
    p -> nx_packet_length      = sizeof(NX_TCP_HEADER) + bytes;
    p -> nx_packet_pool_owner  = &h_pool;

    hdr = (NX_TCP_HEADER *)p -> nx_packet_prepend_ptr;
    memset(hdr, 0, sizeof(*hdr));
    hdr -> nx_tcp_header_word_0   = (80UL << NX_SHIFT_BY_16) | s -> nx_tcp_socket_port;
    hdr -> nx_tcp_sequence_number = s -> nx_tcp_socket_rx_sequence + ahead;
    hdr -> nx_tcp_header_word_3   = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | 65535UL;

    h_pkt_next++;

    (VOID)_nx_tcp_socket_state_data_check(s, p);
}

static void h_run(NX_TCP_SOCKET *s, ULONG segs)
{
    h_run_at(s, segs, 0);
}

static ULONG h_unacked(NX_TCP_SOCKET *s)
{
    return s -> nx_tcp_socket_rx_sequence - s -> nx_tcp_socket_rx_sequence_acked;
}

/* A, B: the tail of an unaligned burst, with and without the pass. */
static void a_an_unaligned_tail_is_acknowledged_at_the_pass_end(void)
{
    h_fixture();

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 16);
    h_check(h_acks == 1, "a full 16-segment run was not acknowledged at once");
    h_run(&h_a, 14);
    h_check(h_acks == 1, "the 14-segment tail was acknowledged before the pass ended");
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 2, "the 16 + 14 tail was not acknowledged at the pass end");
    h_check(h_unacked(&h_a) == 0, "data was left unacknowledged after the pass");
    h_read_all(&h_a);

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 16);
    h_run(&h_a, 2);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 4, "the 16 + 2 tail was not acknowledged at the pass end");
    h_check(h_unacked(&h_a) == 0, "two segments were left unacknowledged");
}

static void b_without_a_pass_the_tail_waits(void)
{
    h_fixture();

    h_run(&h_a, 16);
    h_run(&h_a, 14);
    h_check(h_acks == 1, "without a pass the tail was acknowledged anyway "
                         "(the condition this fixes is not reproduced)");
    h_check(h_unacked(&h_a) == 14UL * H_MSS, "the tail is not what waits");
}

/* C: an aligned burst costs nothing extra. */
static void c_an_aligned_burst_gets_no_extra_ack(void)
{
    h_fixture();

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 16);
    h_run(&h_a, 16);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 2, "an aligned 16 + 16 burst drew other than two ACKs");
}

/* D: under two full-sized segments stays with the delayed ACK. */
static void d_a_single_segment_tail_keeps_the_delayed_ack(void)
{
    h_fixture();

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 16);
    h_run(&h_a, 1);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 1, "a one-segment tail was acknowledged at the pass end");
    h_check(h_unacked(&h_a) == H_MSS, "the one-segment tail is not left for the timer");
}

/* E: a tail the next run's own ACK covered draws nothing more. */
static void e_no_second_ack_for_what_is_covered(void)
{
    h_fixture();

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 14);
    h_run(&h_a, 16);
    h_check(h_acks == 1, "the run past the threshold did not acknowledge the tail with it");
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 1, "the pass end sent a second ACK for covered data");
}

/* F: only flows the pass took data on. */
static void f_flows_the_pass_did_not_touch_are_left_alone(void)
{
    h_fixture();

    h_run(&h_b, 14);            /* outside any pass: B waits on its timer */
    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 14);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 1 && h_ack_sock == &h_a, "the pass end did not acknowledge the flow it touched");
    h_check(h_unacked(&h_b) == 14UL * H_MSS, "the pass end acknowledged a flow it never touched");
}

/* G: a failed allocation is tried once per pass and left for the timer. */
static void g_a_failed_ack_is_tried_once(void)
{
    h_fixture();

    h_alloc_fails = 1;
    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 14);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_ack_attempts == 1, "the pass end tried other than once");
    h_check(h_unacked(&h_a) == 14UL * H_MSS, "a failed ACK was recorded as sent");

    /* A pass that takes nothing in does nothing: the timer owns it now. */
    h_alloc_fails = 0;
    _nx_tcp_receive_pass_begin(&h_ip);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_ack_attempts == 1, "an empty pass acknowledged an old tail");
}

/* H, I, J: states, nesting, and out-of-order data. */
static void h_only_receiving_states_nesting_and_order(void)
{
    h_fixture();

    _nx_tcp_receive_pass_begin(&h_ip);
    h_run(&h_a, 14);
    h_a.nx_tcp_socket_state = NX_TCP_CLOSE_WAIT;   /* a FIN came in the pass */
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 0, "the pass end acknowledged a socket past its FIN");

    h_fixture();
    _nx_tcp_receive_pass_begin(&h_ip);
    _nx_tcp_receive_pass_begin(&h_ip);             /* a loopback inside the pass */
    h_run(&h_a, 14);
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 0, "an inner pass end acknowledged before the outer");
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_acks == 1, "the outer pass end did not acknowledge");

    h_fixture();
    _nx_tcp_receive_pass_begin(&h_ip);
    h_run_at(&h_a, 14, 10UL * H_MSS);              /* a hole before it */
    _nx_tcp_receive_pass_complete(&h_ip);
    h_check(h_ip.nx_ip_tcp_rx_pass_touched == 0 && h_ack_attempts == h_acks,
            "out-of-order data marked the pass");
}

int main(void)
{
    _nx_tcp_fast_timer_rate     = (NX_IP_PERIODIC_RATE + (NX_TCP_FAST_TIMER_RATE - 1)) / NX_TCP_FAST_TIMER_RATE;
    _nx_tcp_ack_timer_rate      = (NX_IP_PERIODIC_RATE + (NX_TCP_ACK_TIMER_RATE - 1)) / NX_TCP_ACK_TIMER_RATE;
    _nx_tcp_transmit_timer_rate = (NX_IP_PERIODIC_RATE + (NX_TCP_TRANSMIT_TIMER_RATE - 1)) / NX_TCP_TRANSMIT_TIMER_RATE;

    printf("TCP receive pass: tails a burst leaves below the ACK threshold\n");

    a_an_unaligned_tail_is_acknowledged_at_the_pass_end();
    b_without_a_pass_the_tail_waits();
    c_an_aligned_burst_gets_no_extra_ack();
    d_a_single_segment_tail_keeps_the_delayed_ack();
    e_no_second_ack_for_what_is_covered();
    f_flows_the_pass_did_not_touch_are_left_alone();
    g_a_failed_ack_is_tried_once();
    h_only_receiving_states_nesting_and_order();

    printf("%lu checks, %lu failures, %s\n",
           h_checks, h_failures, (h_failures == 0UL) ? "PASS" : "FAIL");

    return (h_failures == 0UL) ? 0 : 1;
}
