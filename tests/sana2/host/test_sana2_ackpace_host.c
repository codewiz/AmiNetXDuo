/*
 * AmiNetXDuo, ACKPACE on the host: which acknowledgments sana2_ackpace.c
 * holds, when it lets them go, and the timer its reader arms for the next.
 * The E-clock is this file's, so every due time is exact.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sana2_internal.h"

#include <proto/timer.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static unsigned long h_checks;
static unsigned long h_failures;

static void h_check(int ok, const char *what)
{
    h_checks++;
    if (!ok)
    {
        h_failures++;
        printf("  FAIL %s\n", what);
    }
}

/* ------------------------------------------------------------------ stubs */

#define H_HZ    715909UL            /* the A3000's NTSC E-clock */

struct Device *TimerBase = (struct Device *)1;
static ULONG   h_clock;             /* E-clock low word, this test's       */

ULONG ReadEClock(struct EClockVal *dest)
{
    dest->ev_hi = 0;
    dest->ev_lo = h_clock;
    return H_HZ;
}

ULONG ami_millis(VOID) { return 0; }
ULONG ami_eclock_rate(VOID) { return H_HZ; }
VOID ami_log(int level, const char *fmt, ...) { (VOID)level; (VOID)fmt; }

VOID Forbid(VOID) { }
VOID Permit(VOID) { }

static struct Task  h_reader_task;
static struct Task  h_other_task;
static struct Task *h_me = &h_reader_task;
static unsigned     h_signals;

struct Task *FindTask(STRPTR name) { (VOID)name; return h_me; }
VOID Signal(struct Task *task, ULONG mask)
{
    (VOID)task; (VOID)mask;
    h_signals++;
}

static struct MsgPort h_port;
struct MsgPort *CreateMsgPort(VOID) { h_port.mp_SigBit = 9; return &h_port; }
VOID DeleteMsgPort(struct MsgPort *port) { (VOID)port; }

static ULONG h_timer_us;            /* the last request's wait            */
static int   h_timer_sends;
static int   h_timer_fired;

BYTE OpenDevice(STRPTR name, ULONG unit, struct IORequest *req, ULONG flags)
{
    (VOID)name; (VOID)unit; (VOID)req; (VOID)flags;
    return 0;
}
VOID CloseDevice(struct IORequest *req) { (VOID)req; }
VOID SendIO(struct IORequest *req)
{
    struct timerequest *tr = (struct timerequest *)req;

    h_timer_us = tr->tr_time.tv_secs * 1000000UL + tr->tr_time.tv_micro;
    h_timer_sends++;
    h_timer_fired = 0;
}
struct IORequest *CheckIO(struct IORequest *req)
{
    return h_timer_fired ? req : NULL;
}
BYTE WaitIO(struct IORequest *req) { (VOID)req; return 0; }
LONG AbortIO(struct IORequest *req) { (VOID)req; return 0; }

/* What leaves: the packets in order, and when. */
#define H_MAXSENT 64
static NX_PACKET *h_sent[H_MAXSENT];
static ULONG      h_sent_at[H_MAXSENT];
static unsigned   h_nsent;

UINT ami_sana2_tx_send_now(AmiSana2If *iface, NX_PACKET *packet,
                           UWORD ether_type, ULONG dst_msw, ULONG dst_lsw)
{
    (VOID)iface; (VOID)ether_type; (VOID)dst_msw; (VOID)dst_lsw;
    if (h_nsent < H_MAXSENT)
    {
        h_sent[h_nsent]    = packet;
        h_sent_at[h_nsent] = h_clock;
        h_nsent++;
    }
    return NX_SUCCESS;
}

/* --------------------------------------------------------------- fixtures */

static AmiSana2If     iface;
static AmiSana2Reader rd;

#define H_NPKT 40
static NX_PACKET h_pkt[H_NPKT];
static UCHAR     h_buf[H_NPKT][128];

/* An IPv4 TCP segment from port 5001 to 1234: `flags`, `ack`, `data` bytes
   of payload behind a 20-byte TCP header. */
static NX_PACKET *seg(int i, UCHAR flags, ULONG ack, ULONG data)
{
    NX_PACKET *p  = &h_pkt[i];
    UCHAR     *ip = h_buf[i];
    UCHAR     *t  = ip + 20;

    memset(p, 0, sizeof(*p));
    memset(ip, 0, sizeof(h_buf[i]));
    ip[0]  = 0x45;
    ip[9]  = 6;
    t[0] = 0x13; t[1] = 0x89;       /* 5001 */
    t[2] = 0x04; t[3] = 0xd2;       /* 1234 */
    t[8]  = (UCHAR)(ack >> 24);
    t[9]  = (UCHAR)(ack >> 16);
    t[10] = (UCHAR)(ack >> 8);
    t[11] = (UCHAR)ack;
    t[12] = 0x50;
    t[13] = flags;

    p->nx_packet_prepend_ptr = ip;
    p->nx_packet_append_ptr  = ip + 40 + data;
    p->nx_packet_length      = 40 + data;
    return p;
}

static NX_PACKET *ack(int i, ULONG a) { return seg(i, 0x10, a, 0); }

/* A pure acknowledgment advertising `win` (the raw field). */
static NX_PACKET *ackw(int i, ULONG a, ULONG win)
{
    NX_PACKET *p = seg(i, 0x10, a, 0);

    h_buf[i][20 + 14] = (UCHAR)(win >> 8);
    h_buf[i][20 + 15] = (UCHAR)win;
    return p;
}

/* Our SYN-ACK offering window scale `ws`: a 24-byte header with the option
   NOP, WS(3) ws. */
static NX_PACKET *synack(int i, UCHAR ws)
{
    NX_PACKET *p = seg(i, 0x12, 0, 0);
    UCHAR     *t = h_buf[i] + 20;

    t[12] = 0x60;
    t[20] = 1; t[21] = 3; t[22] = 3; t[23] = ws;
    p->nx_packet_append_ptr = h_buf[i] + 44;
    p->nx_packet_length     = 44;
    return p;
}

/* 20,000 kbit/s: 286 ticks per 1000 bytes, two segments (2920) = 835. */
#define H_KBPS  20000UL
#define H_TPKB  ((H_HZ * 8UL) / H_KBPS)
#define H_GAP(b) (((ULONG)(b) * H_TPKB) / 1000UL)

static void fixture(void)
{
    memset(&iface, 0, sizeof(iface));
    memset(&rd, 0, sizeof(rd));
    h_clock = 100000UL;
    h_nsent = 0;
    h_signals = 0;
    h_timer_sends = 0;
    h_timer_fired = 0;
    h_me = &h_reader_task;

    ami_sana2_ack_setup(&iface, H_KBPS);
    rd.iface = &iface;
    rd.task  = &h_reader_task;
    ami_sana2_ack_reader_start(&rd);
}

/* ------------------------------------------------------------------ tests */

static void test_setup(void)
{
    printf("ackpace: the rate becomes ticks per 1000 bytes; off holds nothing\n");

    fixture();
    h_check(iface.ack_tpkb == H_TPKB, "286 ticks per KB at 20 Mbit/s");
    h_check(rd.ack_tr_open && iface.ack_task == &h_reader_task,
            "the reader owns the release");

    memset(&iface, 0, sizeof(iface));
    ami_sana2_ack_setup(&iface, 0);
    h_check(iface.ack_tpkb == 0, "ACKPACE 0 is off");
}

static void test_what_is_held(void)
{
    printf("ackpace: only a pure IPv4 acknowledgment is ever held\n");

    fixture();
    /* Start the clock, so anything eligible would now be early. */
    h_check(!ami_sana2_ack_hold(&iface, ack(0, 1000), 0, 0),
            "the first acknowledgment goes at once");

    h_check(!ami_sana2_ack_hold(&iface, seg(1, 0x18, 4000, 100), 0, 0),
            "a segment with data is not held");
    h_check(!ami_sana2_ack_hold(&iface, seg(2, 0x12, 4000, 0), 0, 0),
            "a SYN-ACK is not held");
    h_check(!ami_sana2_ack_hold(&iface, seg(3, 0x11, 4000, 0), 0, 0),
            "a FIN is not held");
    h_check(!ami_sana2_ack_hold(&iface, seg(4, 0x14, 4000, 0), 0, 0),
            "an RST is not held");
    h_check(iface.ackq_count == 0, "nothing waits");

    h_check(ami_sana2_ack_hold(&iface, seg(5, 0x18, 4000, 0), 0, 0),
            "a pure acknowledgment with PSH is held");
}

static void test_clock(void)
{
    ULONG t0;
    ULONG wait;

    printf("ackpace: each acknowledgment leaves one step's time after the last\n");

    fixture();
    t0 = h_clock;
    h_check(!ami_sana2_ack_hold(&iface, ack(0, 10000), 0, 0),
            "an idle line sends the first at once");
    h_check(ami_sana2_ack_hold(&iface, ack(1, 12920), 0, 0),
            "the next, two segments on, waits");
    h_check(ami_sana2_ack_hold(&iface, ack(2, 15840), 0, 0),
            "and the one after it");
    h_check(iface.stats.ack_paced == 2, "two counted as paced");

    wait = ami_sana2_ack_release(&iface);
    h_check(h_nsent == 0, "nothing is due yet");
    h_check(wait == H_GAP(2920), "due one two-segment gap after the first");

    h_clock = t0 + H_GAP(2920);
    wait = ami_sana2_ack_release(&iface);
    h_check(h_nsent == 1 && h_sent[0] == &h_pkt[1], "the second leaves when due");
    h_check(wait == H_GAP(2920), "and the third one gap later");

    h_clock += H_GAP(2920);
    wait = ami_sana2_ack_release(&iface);
    h_check(h_nsent == 2 && h_sent[1] == &h_pkt[2], "the third leaves in order");
    h_check(wait == 0, "nothing left");
}

static void test_window_update_costs_nothing(void)
{
    printf("ackpace: a repeat of the same acknowledgment is charged no time\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 50000), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(1, 52920), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(2, 52920), 0, 0);   /* window update */
    (VOID)ami_sana2_ack_hold(&iface, ack(3, 55840), 0, 0);
    h_clock += H_GAP(2920);
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 1, "the step leaves when due");
    h_clock += H_GAP(2920);
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 3,
            "the update a step later, and the next right behind it");
}

static void test_window_update_is_charged(void)
{
    printf("ackpace: a window update is charged what it opens, scaled\n");

    fixture();
    h_check(!ami_sana2_ack_hold(&iface, synack(0, 2), 0, 0),
            "our SYN-ACK goes, and leaves its window scale behind");
    h_check(iface.ack_ws == 2, "scale 2 learnt");

    (VOID)ami_sana2_ack_hold(&iface, ackw(1, 1000, 2000), 0, 0); /* 8000 B */
    (VOID)ami_sana2_ack_hold(&iface, ackw(2, 1000, 3000), 0, 0); /* +4000 B */
    (VOID)ami_sana2_ack_hold(&iface, ackw(3, 3920, 3000), 0, 0); /* +2920 */
    h_clock += H_GAP(2920);
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 1, "the update leaves after the first's gap");
    h_clock += H_GAP(2920);
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 1, "and what follows waits the 4000 bytes it opened");
    h_clock += H_GAP(4000) - H_GAP(2920);
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 2, "then goes");
}

static void test_window_the_card_holds_is_not_paced(void)
{
    printf("ackpace: a window inside the card's memory is never held\n");

    fixture();
    iface.hw_rx_bytes = 13312;              /* an X-Surf 100's ring */
    (VOID)ami_sana2_ack_hold(&iface, ackw(0, 0, 11680), 0, 0);
    h_check(!ami_sana2_ack_hold(&iface, ackw(1, 5840, 11680), 0, 0),
            "an early acknowledgment at the ring fit goes at once");
    h_check(!ami_sana2_ack_hold(&iface, ackw(2, 11680, 46720), 0, 0),
            "the first past the ring starts the clock and goes");
    h_check(ami_sana2_ack_hold(&iface, ackw(3, 17520, 46720), 0, 0),
            "the next past the ring waits its turn");
    h_check(iface.ack_gro_ports == 0x04d21389UL,
            "and its connection, as a segment arriving on it names it, is the "
            "one GROFRAMES cuts");
}

static void test_late_reader_does_not_burst(void)
{
    printf("ackpace: a reader that comes late restarts the clock, not a burst\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(1, 2920), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(2, 5840), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(3, 8760), 0, 0);

    h_clock += 10UL * H_GAP(2920);          /* the reader was busy */
    (VOID)ami_sana2_ack_release(&iface);
    h_check(h_nsent == 1, "one goes, the rest wait their gap from now");
    h_check(iface.ackq_count == 2, "two still held");
}

static void test_full_queue_goes_out_of_turn(void)
{
    int i;

    printf("ackpace: a full hold queue sends out of turn and counts it\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    for (i = 1; i <= (int)AMI_SANA2_ACKQ; i++)
        h_check(ami_sana2_ack_hold(&iface, ack(i, (ULONG)i * 2920UL), 0, 0),
                "held while there is room");
    h_check(!ami_sana2_ack_hold(&iface, ack(i, (ULONG)i * 2920UL), 0, 0),
            "the one past the queue goes at once");
    h_check(iface.stats.ack_unpaced == 1, "and is counted");
}

static void test_no_reader_no_hold(void)
{
    printf("ackpace: with no reader to release them nothing is held\n");

    fixture();
    ami_sana2_ack_reader_stop(&rd);
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    h_check(!ami_sana2_ack_hold(&iface, ack(1, 2920), 0, 0),
            "an early one goes at once");
}

static void test_reader_timer(void)
{
    ULONG expect;

    printf("ackpace: the reader arms its timer for the next due time\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(1, 2920), 0, 0);

    ami_sana2_ack_reader_pass(&rd);
    expect = (H_GAP(2920) * 1000UL) / (H_HZ / 1000UL);
    h_check(h_timer_sends == 1, "one timer request");
    h_check(h_timer_us == expect, "for the gap, in microseconds");

    ami_sana2_ack_reader_pass(&rd);
    h_check(h_timer_sends == 1, "not armed twice while it runs");

    h_clock += H_GAP(2920);
    h_timer_fired = 1;
    ami_sana2_ack_reader_pass(&rd);
    h_check(h_nsent == 1, "the fired timer's pass releases it");
    h_check(h_timer_sends == 1, "and arms nothing with the queue empty");
}

static void test_other_task_wakes_reader(void)
{
    printf("ackpace: one held from another task wakes the reader\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    h_me = &h_other_task;
    (VOID)ami_sana2_ack_hold(&iface, ack(1, 2920), 0, 0);
    h_check(h_signals == 1, "signalled");
    h_me = &h_reader_task;
    (VOID)ami_sana2_ack_hold(&iface, ack(2, 5840), 0, 0);
    h_check(h_signals == 1, "the reader itself is not");
}

static void test_stop_flushes(void)
{
    printf("ackpace: stopping the reader sends what is held, in order\n");

    fixture();
    (VOID)ami_sana2_ack_hold(&iface, ack(0, 0), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(1, 2920), 0, 0);
    (VOID)ami_sana2_ack_hold(&iface, ack(2, 5840), 0, 0);
    ami_sana2_ack_reader_stop(&rd);
    h_check(h_nsent == 2 && h_sent[0] == &h_pkt[1] && h_sent[1] == &h_pkt[2],
            "both, in order");
    h_check(iface.ack_task == NULL, "and the interface has no reader");
}

int main(void)
{
    test_setup();
    test_what_is_held();
    test_clock();
    test_window_update_costs_nothing();
    test_window_update_is_charged();
    test_window_the_card_holds_is_not_paced();
    test_late_reader_does_not_burst();
    test_full_queue_goes_out_of_turn();
    test_no_reader_no_hold();
    test_reader_timer();
    test_other_task_wakes_reader();
    test_stop_flushes();

    printf("ackpace: %lu checks, %lu failures\n", h_checks, h_failures);
    return h_failures == 0 ? 0 : 1;
}
