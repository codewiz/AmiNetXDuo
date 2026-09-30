/*
 * F-059: CloseSocket() and a closing base's bsd_close_all() without a ThreadX
 * bracket -- adoption refused with the kernel still running, or another Task
 * holding the base's bracket (F-042).  The socket is not released and leaks
 * with its NetX callbacks installed; those reach the base through as_Owner
 * (bsd_event_post), and the base can be closed and freed before they fire.
 * Ownership must pass to another holder, or to nobody.
 *
 * socket.c is #included; the bracket is refused throughout, so the release
 * arm below is linked but never run.  Also bsd_fd_restore(), which puts a
 * Dup2Socket() target back after its replacement was refused (F-055).
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

#define H_FDS  4

static struct AmiSocketBase h_master;
static struct AmiSocketBase h_base;
static struct AmiSocketBase h_other;
static AmiSocket           *h_table[H_FDS];
static AmiSocket           *h_other_table[H_FDS];
static AmiSocket            h_sock[2];
static struct Task          h_task_base, h_task_other;
static int                  h_signals;
static struct Task         *h_signalled;

/* ---- what the unbracketed arms reach ---- */

LONG bsd_nx_enter(struct AmiSocketBase *base) { (VOID)base; return -1; }
VOID bsd_nx_leave(struct AmiSocketBase *base) { (VOID)base; abort(); }

VOID Signal(struct Task *task, ULONG mask)
{
    (VOID)mask;
    h_signals++;
    h_signalled = task;
}

LONG bsd_fail(struct AmiSocketBase *base, LONG code)
{
    base->sb_Errno = code;
    return -1;
}

VOID AddTail(struct List *list, struct Node *node)
{
    node->ln_Succ = (struct Node *)&list->lh_Tail;
    node->ln_Pred = list->lh_TailPred;
    list->lh_TailPred->ln_Succ = node;
    list->lh_TailPred = node;
}

VOID Forbid(VOID) { }
VOID Permit(VOID) { }

VOID bsd_bzero(APTR p, ULONG size) { memset(p, 0, size); }
VOID bsd_bcopy(CONST_APTR src, APTR dst, ULONG size) { memcpy(dst, src, size); }

#include "socket.c"

/* The release arm, linked and never run: the bracket is always refused. */
VOID _nx_tcp_packet_send_fin(NX_TCP_SOCKET *s, ULONG seq) { (VOID)s; (VOID)seq; abort(); }
VOID _nx_tcp_packet_send_rst(NX_TCP_SOCKET *s, NX_TCP_HEADER *h) { (VOID)s; (VOID)h; abort(); }
UINT _nxe_packet_release(NX_PACKET **p) { (VOID)p; abort(); }
UINT _nxe_tcp_client_socket_unbind(NX_TCP_SOCKET *s) { (VOID)s; abort(); }
UINT _nxe_tcp_server_socket_unaccept(NX_TCP_SOCKET *s) { (VOID)s; abort(); }
UINT _nxe_tcp_server_socket_unlisten(NX_IP *ip, UINT port) { (VOID)ip; (VOID)port; abort(); }
UINT _nxe_tcp_socket_delete(NX_TCP_SOCKET *s) { (VOID)s; abort(); }
UINT _nxe_tcp_socket_disconnect(NX_TCP_SOCKET *s, ULONG w) { (VOID)s; (VOID)w; abort(); }
UINT _nxe_tcp_socket_receive_notify(NX_TCP_SOCKET *s,
                                    VOID (*fn)(NX_TCP_SOCKET *))
{ (VOID)s; (VOID)fn; abort(); }
UINT _nxe_udp_socket_delete(NX_UDP_SOCKET *s) { (VOID)s; abort(); }
UINT _nxe_udp_socket_unbind(NX_UDP_SOCKET *s) { (VOID)s; abort(); }
ULONG _tx_time_get(VOID) { abort(); }
UINT _txe_mutex_get(TX_MUTEX *m, ULONG w) { (VOID)m; (VOID)w; abort(); }
UINT _txe_mutex_put(TX_MUTEX *m) { (VOID)m; abort(); }
VOID ami_free(APTR p) { (VOID)p; abort(); }
VOID ami_mem_socket_delta(LONG d) { (VOID)d; abort(); }
VOID bsd_mcast_close(AmiSocket *s) { (VOID)s; abort(); }
VOID bsd_raw_close(AmiSocket *s) { (VOID)s; abort(); }


static void h_link(struct AmiSocketBase *b)
{
    AddTail((struct List *)&h_master.sb_Children, (struct Node *)&b->sb_Node);
}

static void h_reset(void)
{
    struct List *l = (struct List *)&h_master.sb_Children;

    memset(&h_master, 0, sizeof(h_master));
    memset(&h_base, 0, sizeof(h_base));
    memset(&h_other, 0, sizeof(h_other));
    memset(h_table, 0, sizeof(h_table));
    memset(h_other_table, 0, sizeof(h_other_table));
    memset(h_sock, 0, sizeof(h_sock));

    l->lh_Head     = (struct Node *)&l->lh_Tail;
    l->lh_Tail     = NULL;
    l->lh_TailPred = (struct Node *)&l->lh_Head;
    h_link(&h_base);
    h_link(&h_other);

    h_base.sb_Master = h_other.sb_Master = &h_master;
    h_base.sb_Table = h_table;
    h_base.sb_TableSize = H_FDS;
    h_other.sb_Table = h_other_table;
    h_other.sb_TableSize = H_FDS;
    h_base.sb_Task = &h_task_base;
    h_other.sb_Task = &h_task_other;
    h_base.sb_EventSigMask = 1UL << 10;
    h_other.sb_EventSigMask = 1UL << 11;

    h_signals = 0;
    h_signalled = NULL;
}

/* SBTC_FDCALLBACK: the last action seen, and the answer to give. */
static LONG h_fdcb_action;
static LONG h_fdcb_answer;

static LONG h_fdcb(LONG fd, LONG action)
{
    (VOID)fd;
    h_fdcb_action = action;
    return h_fdcb_answer;
}

static void t_fd_restore(void)
{
    h_reset();
    h_base.sb_FDCallback = h_fdcb;
    h_fdcb_action = -1;
    h_fdcb_answer = 0;
    CHECK(bsd_fd_restore(&h_base, 1, &h_sock[0]) == 0 && h_table[1] == &h_sock[0],
          "bsd_fd_restore puts the entry back");
    CHECK(h_fdcb_action == FDCB_ALLOC, "and announces it with FDCB_ALLOC");

    h_fdcb_action = -1;
    CHECK(bsd_fd_restore(&h_base, 1, &h_sock[1]) != 0 && h_table[1] == &h_sock[0] &&
          h_fdcb_action == -1,
          "a slot taken meanwhile is refused, with no callback");

    h_table[1] = NULL;
    h_fdcb_answer = 5;
    CHECK(bsd_fd_restore(&h_base, 1, &h_sock[0]) != 0 && h_table[1] == NULL,
          "a refused FDCB_ALLOC leaves the slot empty");

    CHECK(bsd_fd_restore(&h_base, H_FDS, &h_sock[0]) != 0,
          "a descriptor past the table is refused");
    h_base.sb_FDCallback = NULL;
}

int main(void)
{
    t_fd_restore();

    /* CloseSocket() with the bracket refused: the socket leaks, and its
       callbacks no longer reach this base. */
    h_reset();
    h_sock[0].as_RefCount = 1;
    h_sock[0].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    CHECK(bsd_CloseSocket(0, &h_base) == 0, "CloseSocket succeeds");
    CHECK(h_table[0] == NULL, "the descriptor is gone");
    CHECK(h_sock[0].as_RefCount == 1, "the socket is not released (it leaks)");
    CHECK(h_sock[0].as_Owner == NULL, "and no longer names this base");

    /* The same socket held by another opener too: that opener owns it. */
    h_reset();
    h_sock[0].as_RefCount = 2;
    h_sock[0].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    h_other_table[1] = &h_sock[0];
    CHECK(bsd_CloseSocket(0, &h_base) == 0, "CloseSocket of a shared socket");
    CHECK(h_sock[0].as_Owner == &h_other, "the other holder owns it");
    CHECK(h_signals == 1 && h_signalled == &h_task_other,
          "and is signalled once");

    /* A closing base with the bracket refused: every socket leaks, none
       keeps the base as its owner.  A Dup2Socket() alias frees last. */
    h_reset();
    h_sock[0].as_RefCount = 2;
    h_sock[0].as_Owner = &h_base;
    h_sock[1].as_RefCount = 1;
    h_sock[1].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    h_table[1] = &h_sock[1];
    h_table[2] = &h_sock[0];                    /* an alias of fd 0 */
    bsd_close_all(&h_base);
    CHECK(h_table[0] == NULL && h_table[1] == NULL && h_table[2] == NULL,
          "every descriptor is gone");
    CHECK(h_sock[0].as_Owner == NULL && h_sock[1].as_Owner == NULL,
          "and no leaked socket names the closing base");

    printf("unbracketed_close: %lu checks, %lu failures\n",
           h_checks, h_failures);
    return (h_failures != 0) ? 1 : 0;
}
