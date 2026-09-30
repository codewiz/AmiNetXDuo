/*
 * F-059: a release that CloseSocket(), bsd_close_all() or a Dup2Socket()
 * refusal could not make without a ThreadX bracket is owed, and the next
 * bracketed close of any base pays it.  Before, the socket leaked for the
 * life of the stack.
 *
 * socket.c is #included.  The bracket is switched per step; sockets are
 * marked ASF_DELETED, so paying the last release reaches bsd_socket_dispose()
 * and ami_free(), which is what this watches.  Only CloseSocket(),
 * bsd_close_all(), reference counts and frees are observed, so the same test
 * builds against a socket.c without the deferral and fails there.
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
static AmiSocket            h_sock[4];
static struct Task          h_task_base, h_task_other;
static int                  h_signals;
static struct Task         *h_signalled;

static int                  h_bracket;
static int                  h_frees;
static APTR                 h_freed;
static APTR                 h_freed_all[16];
static AmiNetStack         *h_stack;            /* netstack_get()          */
static BOOL                 h_quiet;            /* netstack_can_unload()   */

AmiNetStack *netstack_get(VOID) { return h_stack; }
BOOL netstack_can_unload(VOID) { return h_quiet; }

LONG bsd_nx_enter(struct AmiSocketBase *base) { (VOID)base; return h_bracket ? 0 : -1; }
VOID bsd_nx_leave(struct AmiSocketBase *base) { (VOID)base; }

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

/* Only ASF_DELETED sockets are destroyed here, so NetX is never reached. */
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
ULONG _tx_time_get(VOID) { return 0; }
UINT _txe_mutex_get(TX_MUTEX *m, ULONG w) { (VOID)m; (VOID)w; abort(); }
UINT _txe_mutex_put(TX_MUTEX *m) { (VOID)m; abort(); }
APTR ami_alloc(ULONG n) { (VOID)n; abort(); }
VOID ami_free(APTR p)
{
    if (h_frees < 16)
        h_freed_all[h_frees] = p;
    h_frees++;
    h_freed = p;
}

/* TRUE when p was freed exactly once. */
static int h_freed_once(APTR p)
{
    int i, n = 0;

    for (i = 0; i < h_frees && i < 16; i++)
        if (h_freed_all[i] == p)
            n++;
    return n == 1;
}
VOID ami_mem_socket_delta(LONG d) { (VOID)d; }
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
    h_sock[0].as_Flags = ASF_DELETED;
    h_sock[1].as_Flags = ASF_DELETED;
    h_sock[2].as_Flags = ASF_DELETED;
    h_sock[3].as_Flags = ASF_DELETED;
    bsd_closing_head = NULL;
    bsd_defer_head   = NULL;
    h_stack = NULL;
    h_quiet = TRUE;

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
    h_frees = 0;
    h_freed = NULL;
}

int main(void)
{
    /* The last reference, closed with no bracket, then another base's
       bracketed close of an unrelated socket. */
    h_reset();
    h_sock[0].as_RefCount = 1;
    h_sock[0].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    h_sock[1].as_RefCount = 2;
    h_sock[1].as_Owner = &h_other;
    h_other_table[0] = &h_sock[1];
    h_bracket = 0;
    CHECK(bsd_CloseSocket(0, &h_base) == 0 && h_table[0] == NULL,
          "unbracketed CloseSocket frees the descriptor");
    CHECK(h_frees == 0 && h_sock[0].as_RefCount == 1,
          "and releases nothing yet");
    h_bracket = 1;
    CHECK(bsd_CloseSocket(0, &h_other) == 0, "a bracketed close elsewhere");
    CHECK(h_sock[1].as_RefCount == 1, "releases its own socket once");
    CHECK(h_frees == 1 && h_freed == &h_sock[0],
          "and pays the owed release: the orphan is freed");
    h_bracket = 0;
    CHECK(bsd_CloseSocket(0, &h_base) == -1, "fd 0 of the first base is gone");
    h_bracket = 1;
    h_other_table[1] = &h_sock[1];
    CHECK(bsd_CloseSocket(1, &h_other) == 0 && h_frees == 2 &&
          h_freed == &h_sock[1], "nothing is paid twice");

    /* Shared with another opener: the owed release keeps it alive until
       that opener's own close, and it is freed once. */
    h_reset();
    h_sock[0].as_RefCount = 2;
    h_sock[0].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    h_other_table[1] = &h_sock[0];
    h_bracket = 0;
    CHECK(bsd_CloseSocket(0, &h_base) == 0 && h_sock[0].as_Owner == &h_other,
          "unbracketed close of a shared socket hands it to the other holder");
    h_bracket = 1;
    CHECK(bsd_CloseSocket(1, &h_other) == 0, "the other holder closes it");
    CHECK(h_frees == 1 && h_freed == &h_sock[0],
          "both releases are paid and it is freed once");

    /* A closing base with no bracket, a Dup2Socket() alias among its
       descriptors: two releases owed on one socket, one on another. */
    h_reset();
    h_sock[0].as_RefCount = 2;
    h_sock[0].as_Owner = &h_base;
    h_sock[1].as_RefCount = 1;
    h_sock[1].as_Owner = &h_base;
    h_table[0] = &h_sock[0];
    h_table[1] = &h_sock[1];
    h_table[2] = &h_sock[0];
    h_bracket = 0;
    bsd_close_all(&h_base);
    CHECK(h_frees == 0 && h_sock[0].as_Owner == NULL &&
          h_sock[1].as_Owner == NULL,
          "unbracketed bsd_close_all releases nothing and names nobody");
    h_bracket = 1;
    h_other_table[3] = &h_sock[0];              /* any bracketed close */
    h_sock[0].as_RefCount++;
    CHECK(bsd_CloseSocket(3, &h_other) == 0, "a bracketed close elsewhere");
    CHECK(h_frees == 2, "pays all three owed releases: both sockets freed");

    /* ---- the last opener could not bracket (F-059) ----------------------
       What it could not drain: sock 0 a parked close, sock 1 owing its last
       release, sock 2 owing one release with a reference nobody owes (still
       named by something live), sock 3 left in no list. */
#define H_ORPHANS()                                                          \
    do {                                                                     \
        h_reset();                                                           \
        h_sock[0].as_Flags |= ASF_CLOSING;                                   \
        bsd_closing_head = &h_sock[0];                                       \
        h_sock[1].as_RefCount = 1;                                           \
        h_sock[2].as_RefCount = 2;                                           \
        h_bracket = 0;                                                       \
        bsd_socket_defer(&h_sock[1]);                                        \
        bsd_socket_defer(&h_sock[2]);                                        \
    } while (0)

    /* The stack is destroyed and quiet: memory only, each freed once. */
    H_ORPHANS();
    h_stack = NULL;
    h_quiet = TRUE;
    bsd_orphans_reclaim();
    CHECK(h_frees == 2 && h_freed_once(&h_sock[0]) && h_freed_once(&h_sock[1]),
          "a dead, quiet stack: the parked close and the owed socket are freed "
          "once each, and nothing in NetX is called");
    CHECK(!h_freed_once(&h_sock[2]) && !h_freed_once(&h_sock[3]),
          "one still named by something live is not freed");
    CHECK(bsd_closing_head == NULL && bsd_defer_head == NULL,
          "and both lists are empty");
    bsd_orphans_reclaim();
    CHECK(h_frees == 2, "a second call frees nothing again");

    /* Destroyed, but a kernel that did not stop: forgotten, not freed. */
    H_ORPHANS();
    h_stack = NULL;
    h_quiet = FALSE;
    bsd_orphans_reclaim();
    CHECK(h_frees == 0 && bsd_closing_head == NULL && bsd_defer_head == NULL,
          "a stack that is not provably quiet: nothing freed, lists emptied");

    /* Still up for another holder: kept, then paid by the next bracketed
       close, exactly once. */
    H_ORPHANS();
    bsd_closing_head = NULL;                    /* only the owed releases */
    h_stack = (AmiNetStack *)&h_master;
    bsd_orphans_reclaim();
    CHECK(h_frees == 0 && bsd_defer_head != NULL,
          "a stack still up: the owed releases are kept");
    h_bracket = 1;
    h_other_table[0] = &h_sock[3];
    h_sock[3].as_RefCount = 2;
    h_sock[3].as_Owner = &h_other;
    CHECK(bsd_CloseSocket(0, &h_other) == 0 && h_frees == 1 &&
          h_freed_once(&h_sock[1]) && bsd_defer_head == NULL,
          "the next bracketed close pays them: freed once");
    CHECK(h_sock[2].as_RefCount == 1, "and the live one only loses its owed "
          "reference");

    /* A restart: the startup guard empties a dead stack's lists before
       anything on the new stack can sweep them. */
    H_ORPHANS();
    h_stack = NULL;
    h_quiet = TRUE;
    bsd_orphans_reclaim();                      /* library.c, before startup */
    h_stack = (AmiNetStack *)&h_master;         /* the new stack */
    h_bracket = 1;
    h_other_table[1] = &h_sock[3];
    h_sock[3].as_RefCount = 2;
    CHECK(bsd_CloseSocket(1, &h_other) == 0 && h_frees == 2 &&
          bsd_closing_head == NULL && bsd_defer_head == NULL,
          "after a restart the new stack's sweep finds nothing of the old");

    printf("deferred_release: %lu checks, %lu failures\n",
           h_checks, h_failures);
    return (h_failures != 0) ? 1 : 0;
}
