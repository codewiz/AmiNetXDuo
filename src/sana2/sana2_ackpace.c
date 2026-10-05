/*
 * AmiNetXDuo, SANA-II acknowledgment pacing (the interface's ACKPACE).
 *
 * WHAT IT IS FOR.  A sender whose window is the limit sends what each
 * acknowledgment opens, at once and back to back.  This reader acknowledges
 * a segment when TCP has handled it, and TCP is only part of what a frame
 * costs a 68k: the copy off the card and the copy to the application come
 * on either side of it.  Measured on an A3000 (68060 at 50 MHz, X-Surf 100,
 * GROFRAMES=2, a 25 ms path): acknowledgments left evenly, 543 us apart,
 * each opening two segments -- a sender clocked at ~43 Mbit/s against the
 * ~22 the machine sustains, so the eight-frame ring overran.  The same
 * machine took a sender paced at 16 Mbit/s with no overrun at all.
 *
 * SO: a pure acknowledgment (IPv4 TCP, ACK the only flag that matters, no
 * data) leaves no sooner than the bytes the one before it opened take at
 * ACKPACE kbit/s.  "Opened" is how far it moved the sender's right edge,
 * acknowledgment plus window: a window update repeats the acknowledgment
 * and still lets a whole window go (on the A3000 half the long trains of a
 * paced LAN run followed one).  The window is scaled by the shift our own
 * SYN or SYN-ACK offered, read as it passes through here.
 *
 * ONLY A WINDOW THE CARD CANNOT HOLD IS PACED.  A sender kept inside the
 * card's own memory (hw_rx_bytes: its ring, or what it measured with the
 * partner pausing for it) cannot overrun it however it bursts, so an
 * acknowledgment advertising no more than that goes at once: a LAN
 * connection at its ring fit, and every connection on a link with PAUSE
 * agreed.  What is paced is the long path's larger window (TCPWANWINDOW),
 * where the window, not the card, would otherwise set the burst.  One that is early waits in a short queue on the
 * interface, in order; the reader lets it go when it is due -- at the top of
 * each of its passes, and from a timer.device request when nothing else
 * would wake it, which is the case that matters: a sender waiting for
 * acknowledgments sends nothing.  An acknowledgment that finds the line idle
 * and nothing waiting goes at once.  A full queue, a segment with data, a
 * SYN, FIN or RST, and anything not IPv4 are never held.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sana2_internal.h"

#include <proto/exec.h>
#include <proto/timer.h>
#include <devices/timer.h>
/* BeginIO(): a macro over the device's own vector, no amiga.lib to link. */
#include <inline/alib.h>

extern struct Device *TimerBase;

/* The most bytes one acknowledgment is charged for: a jump larger than this
   is a recovery or a new flow, not a step of the clock. */
#define AMI_ACK_GAP_BYTES_MAX   16384UL
/* What an acknowledgment of an unknown step is charged: two segments. */
#define AMI_ACK_GAP_BYTES_DEF   2920UL

static ULONG ami_ack_now(VOID)
{
    struct EClockVal ev;

    if (TimerBase == NULL)
        return 0UL;

    (VOID)ReadEClock(&ev);

    return ev.ev_lo;
}

/*
 * ticks per 1000 bytes = E-clock Hz * 8 bits / kbit/s.  32-bit throughout: a
 * shared library must not pull __udivdi3 out of libgcc (compat.c).  At
 * 715,909 Hz and 20,000 kbit/s that is 286, and a 16 KB step is 4.7 million
 * at most, so the product below never wraps.
 */
VOID ami_sana2_ack_setup(AmiSana2If *iface, ULONG kbps)
{
    ULONG hz;

    iface->ack_tpkb   = 0UL;
    iface->ackq_head  = 0;
    iface->ackq_count = 0;
    iface->ack_clock  = FALSE;
    iface->ack_task   = NULL;
    iface->ack_wake   = 0UL;

    if (kbps == 0UL)
        return;

    (VOID)ami_millis();             /* opens timer.device, sets TimerBase */
    hz = ami_eclock_rate();
    if (hz == 0UL)
    {
        AMI_WARN("sana2: %s: ACKPACE needs timer.device; acknowledgments "
                 "go at once", iface->device);
        return;
    }

    iface->ack_tpkb = (hz * 8UL) / kbps;
    if (iface->ack_tpkb == 0UL)
        iface->ack_tpkb = 1UL;
    AMI_INFO("sana2: %s: acknowledgments paced at %lu kbit/s (%lu ticks/KB)",
             iface->device, (unsigned long)kbps,
             (unsigned long)iface->ack_tpkb);
}

/*
 * A pure acknowledgment, and what it acknowledges.  The IP and TCP headers
 * are in the first buffer of anything NetX builds as a bare ACK; anything
 * else is simply not held.
 */
/* Our SYN or SYN-ACK on its way out: remember the window scale it offers
   for its connection, so the windows its acknowledgments carry can be read
   in bytes.  One connection at a time, like the step below. */
static VOID ami_ack_learn_scale(AmiSana2If *iface, const UCHAR *tcp,
                                ULONG thl, ULONG ports)
{
    ULONG i = 20UL;

    while (i < thl)
    {
        UCHAR kind = tcp[i];

        if (kind == 0U)
            break;
        if (kind == 1U)
        {
            i++;
            continue;
        }
        if (i + 1UL >= thl || tcp[i + 1] < 2U)
            break;
        if (kind == 3U && tcp[i + 1] == 3U && i + 2UL < thl)
        {
            iface->ack_ws_ports = ports;
            iface->ack_ws       = (UBYTE)((tcp[i + 2] > 14U) ? 14U
                                                             : tcp[i + 2]);
            return;
        }
        i += tcp[i + 1];
    }
    iface->ack_ws_ports = ports;
    iface->ack_ws       = 0;
}

static BOOL ami_ack_parse(AmiSana2If *iface, const NX_PACKET *packet,
                          ULONG *ack, ULONG *ports, ULONG *win)
{
    const UCHAR *ip = packet->nx_packet_prepend_ptr;
    const UCHAR *tcp;
    ULONG        ihl;
    ULONG        thl;
    ULONG        avail;

    avail = (ULONG)(packet->nx_packet_append_ptr - ip);
    if (avail < 40UL || (ip[0] >> 4) != 4U || ip[9] != 6U)
        return FALSE;

    ihl = (ULONG)(ip[0] & 0x0FU) << 2;
    if (ihl < 20UL || avail < ihl + 20UL)
        return FALSE;

    tcp = ip + ihl;
    thl = (ULONG)(tcp[12] >> 4) << 2;
    if (thl < 20UL || avail < ihl + thl)
        return FALSE;

    *ports = ((ULONG)tcp[0] << 24) | ((ULONG)tcp[1] << 16) |
             ((ULONG)tcp[2] << 8)  |  (ULONG)tcp[3];

    if ((tcp[13] & 0x02U) != 0U)
    {
        ami_ack_learn_scale(iface, tcp, thl, *ports);
        return FALSE;
    }

    if (packet->nx_packet_length != ihl + thl)
        return FALSE;                       /* carries data               */

    /* ACK set; SYN, FIN, RST clear.  PSH and the ECN bits do not matter. */
    if ((tcp[13] & 0x17U) != 0x10U)
        return FALSE;

    *win   = ((ULONG)tcp[14] << 8) | (ULONG)tcp[15];
    *ack   = ((ULONG)tcp[8] << 24) | ((ULONG)tcp[9] << 16) |
             ((ULONG)tcp[10] << 8) |  (ULONG)tcp[11];

    return TRUE;
}

BOOL ami_sana2_ack_hold(AmiSana2If *iface, NX_PACKET *packet,
                        ULONG dst_msw, ULONG dst_lsw)
{
    ULONG ack;
    ULONG ports;
    ULONG win;
    ULONG edge;
    ULONG step;
    ULONG gap;
    ULONG now;
    BOOL  held = FALSE;

    if (!ami_ack_parse(iface, packet, &ack, &ports, &win))
        return FALSE;

    now = ami_ack_now();

    Forbid();

    /* What this acknowledgment opens: how far it moves the right edge past
       the last one of the same connection -- the acknowledgment's step, or
       more when the window grew with it, or a window update's whole
       opening.  A repeat that moves nothing is charged nothing. */
    if (ports == iface->ack_ws_ports)
        win <<= iface->ack_ws;
    edge = ack + win;
    step = AMI_ACK_GAP_BYTES_DEF;
    if (ports == iface->ack_prev_ports)
    {
        ULONG by_ack  = ack - iface->ack_prev_ack;
        ULONG by_edge = edge - iface->ack_prev_edge;

        if ((LONG)by_ack < 0)
            by_ack = 0UL;
        if ((LONG)by_edge < 0)
            by_edge = 0UL;
        step = (by_edge > by_ack) ? by_edge : by_ack;
    }
    if (step > AMI_ACK_GAP_BYTES_MAX)
        step = AMI_ACK_GAP_BYTES_MAX;
    iface->ack_prev_ack   = ack;
    iface->ack_prev_edge  = edge;
    iface->ack_prev_ports = ports;
    gap = (step * iface->ack_tpkb) / 1000UL;

    /* A window the card holds: never held, and it does not hold up what
       follows either. */
    if (iface->hw_rx_bytes != 0UL && win <= iface->hw_rx_bytes)
    {
        Permit();
        return FALSE;
    }

    /* This connection is the paced one: its arriving runs are cut at
       GROFRAMES (sana2_rx.c), so its acknowledgments come in small steps. */
    iface->ack_gro_ports = (ports << 16) | (ports >> 16);

    if (iface->ackq_count == 0 &&
        (!iface->ack_clock || (LONG)(now - iface->ack_next) >= 0))
    {
        /* The line is idle: this one goes now and starts the clock. */
        iface->ack_clock = TRUE;
        iface->ack_next  = now + gap;
    }
    else if (iface->ackq_count < (UWORD)AMI_SANA2_ACKQ &&
             iface->ack_task != NULL)
    {
        AmiAckHeld *h = &iface->ackq[(iface->ackq_head + iface->ackq_count) %
                                     AMI_SANA2_ACKQ];

        h->packet  = packet;
        h->dst_msw = dst_msw;
        h->dst_lsw = dst_lsw;
        h->gap     = gap;
        iface->ackq_count++;
        iface->stats.ack_paced++;
        held = TRUE;
    }
    else
    {
        /* A full queue, or no reader to release it: out of turn. */
        iface->stats.ack_unpaced++;
    }

    Permit();

    /* The reader arms its timer at the top of its next pass; one held from
       another task has to wake it for that. */
    if (held && iface->ack_task != FindTask(NULL))
        Signal(iface->ack_task, iface->ack_wake);

    return held;
}

/*
 * Every held acknowledgment that is due goes, in order.  The answer is the
 * E-clock ticks until the next one is due, 0 when none is held.  A reader
 * that came late does not send the backlog as a burst: the clock restarts
 * from now when it has fallen more than one gap behind.
 */
ULONG ami_sana2_ack_release(AmiSana2If *iface)
{
    for (;;)
    {
        AmiAckHeld h;
        ULONG      now = ami_ack_now();
        ULONG      base;

        Forbid();
        if (iface->ackq_count == 0)
        {
            Permit();
            return 0UL;
        }
        if ((LONG)(iface->ack_next - now) > 0)
        {
            ULONG wait = iface->ack_next - now;

            Permit();
            return (wait != 0UL) ? wait : 1UL;
        }

        h = iface->ackq[iface->ackq_head];
        iface->ackq_head = (UWORD)((iface->ackq_head + 1) % AMI_SANA2_ACKQ);
        iface->ackq_count--;

        base = ((LONG)(now - iface->ack_next) > (LONG)h.gap) ? now
                                                             : iface->ack_next;
        iface->ack_next = base + h.gap;
        Permit();

        (VOID)ami_sana2_tx_send_now(iface, h.packet, AMI_ETHERTYPE_IPV4,
                                    h.dst_msw, h.dst_lsw);
    }
}

/* Everything held goes now, in order: the reader is stopping. */
VOID ami_sana2_ack_flush(AmiSana2If *iface)
{
    for (;;)
    {
        AmiAckHeld h;

        Forbid();
        if (iface->ackq_count == 0)
        {
            iface->ack_clock = FALSE;
            Permit();
            return;
        }
        h = iface->ackq[iface->ackq_head];
        iface->ackq_head = (UWORD)((iface->ackq_head + 1) % AMI_SANA2_ACKQ);
        iface->ackq_count--;
        Permit();

        (VOID)ami_sana2_tx_send_now(iface, h.packet, AMI_ETHERTYPE_IPV4,
                                    h.dst_msw, h.dst_lsw);
    }
}

/* ------------------------------------------------------- the reader's timer */

/*
 * The reader that releases this interface's acknowledgments: its own port
 * and timer.device request, MICROHZ.  Without either the interface simply
 * does not pace (ack_task stays NULL and nothing is held).
 */
VOID ami_sana2_ack_reader_start(AmiSana2Reader *rd)
{
    AmiSana2If *iface = rd->iface;

    rd->ack_port    = NULL;
    rd->ack_tr_open = FALSE;
    rd->ack_tr_busy = FALSE;
    rd->ack_mask    = 0UL;

    if (iface->ack_tpkb == 0UL)
        return;

    rd->ack_port = CreateMsgPort();
    if (rd->ack_port == NULL)
        goto fail;

    rd->ack_tr.tr_node.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    rd->ack_tr.tr_node.io_Message.mn_ReplyPort    = rd->ack_port;
    rd->ack_tr.tr_node.io_Message.mn_Length       = sizeof(rd->ack_tr);
    if (OpenDevice((STRPTR)TIMERNAME, UNIT_MICROHZ,
                   (struct IORequest *)&rd->ack_tr, 0) != 0)
        goto fail;

    rd->ack_tr_open = TRUE;
    rd->ack_mask    = 1UL << rd->ack_port->mp_SigBit;

    Forbid();
    iface->ack_task = rd->task;
    iface->ack_wake = rd->ack_mask;
    Permit();
    return;

fail:
    if (rd->ack_port != NULL)
    {
        DeleteMsgPort(rd->ack_port);
        rd->ack_port = NULL;
    }
    iface->ack_tpkb = 0UL;
    AMI_WARN("sana2: %s: no timer for ACKPACE; acknowledgments go at once",
             iface->device);
}

/*
 * Once per pass, before the reader may sleep: collect a timer that has
 * fired, let go what is due, and arm the timer for the next one if it is not
 * already running.  A timer armed for a later deadline than a new one is
 * fine: the queue only ever grows later.
 */
VOID ami_sana2_ack_reader_pass(AmiSana2Reader *rd)
{
    ULONG wait;
    ULONG hz;
    ULONG us;

    if (!rd->ack_tr_open)
        return;

    if (rd->ack_tr_busy && CheckIO((struct IORequest *)&rd->ack_tr) != NULL)
    {
        (VOID)WaitIO((struct IORequest *)&rd->ack_tr);
        rd->ack_tr_busy = FALSE;
    }

    wait = ami_sana2_ack_release(rd->iface);
    if (wait == 0UL || rd->ack_tr_busy)
        return;

    /* ticks -> microseconds, 32-bit: ticks * 1000 / (Hz / 1000).  A wait is
       a fraction of a second; clamp it to one so the product cannot wrap. */
    hz = ami_eclock_rate();
    if (hz < 1000UL)
        hz = 709379UL;
    if (wait > hz)
        wait = hz;
    us = (wait * 1000UL) / (hz / 1000UL);
    if (us == 0UL)
        us = 1UL;

    rd->ack_tr.tr_node.io_Command = TR_ADDREQUEST;
    rd->ack_tr.tr_time.tv_secs    = us / 1000000UL;
    rd->ack_tr.tr_time.tv_micro   = us % 1000000UL;
    SendIO((struct IORequest *)&rd->ack_tr);
    rd->ack_tr_busy = TRUE;
}

VOID ami_sana2_ack_reader_stop(AmiSana2Reader *rd)
{
    AmiSana2If *iface = rd->iface;

    if (rd->ack_tr_open)
    {
        Forbid();
        iface->ack_task = NULL;
        iface->ack_wake = 0UL;
        Permit();

        if (rd->ack_tr_busy)
        {
            (VOID)AbortIO((struct IORequest *)&rd->ack_tr);
            (VOID)WaitIO((struct IORequest *)&rd->ack_tr);
            rd->ack_tr_busy = FALSE;
        }
        CloseDevice((struct IORequest *)&rd->ack_tr);
        rd->ack_tr_open = FALSE;
    }

    ami_sana2_ack_flush(iface);

    if (rd->ack_port != NULL)
    {
        DeleteMsgPort(rd->ack_port);
        rd->ack_port = NULL;
    }
    rd->ack_mask = 0UL;
}
