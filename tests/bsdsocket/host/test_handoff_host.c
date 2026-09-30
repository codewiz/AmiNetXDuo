/*
 * handoff.c on the host: listeners are ordinary releasable sockets, as they
 * are in AmiTCP and Roadshow.
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
static unsigned long failures;

#define CHECK(c, what)                                                        \
    do {                                                                      \
        checks++;                                                             \
        if (!(c)) {                                                           \
            failures++;                                                       \
            printf("  FAIL %s\n", (what));                                  \
        }                                                                     \
    } while (0)

static AmiSocket *tables[4][4];
static struct AmiSocketBase master_base;
static struct AmiSocketBase source_base;
static struct AmiSocketBase target_base;
static struct AmiSocketBase third_base;

/* Signal(), recorded: which task was told, and how often. */
static struct Task  task_a, task_b, task_c;
static struct Task *signalled_task;
static ULONG        signalled_mask;
static int          signals;

VOID Signal(struct Task *task, ULONG mask)
{
    signalled_task = task;
    signalled_mask = mask;
    signals++;
}

VOID AddTail(struct List *list, struct Node *node)
{
    node->ln_Succ = (struct Node *)&list->lh_Tail;
    node->ln_Pred = list->lh_TailPred;
    list->lh_TailPred->ln_Succ = node;
    list->lh_TailPred = node;
}

VOID Remove(struct Node *node)
{
    node->ln_Pred->ln_Succ = node->ln_Succ;
    node->ln_Succ->ln_Pred = node->ln_Pred;
}

struct Node *RemHead(struct List *list)
{
    struct Node *node = list->lh_Head;

    if (node->ln_Succ == NULL)
        return NULL;
    Remove(node);
    return node;
}

VOID ObtainSemaphore(struct SignalSemaphore *sem) { (VOID)sem; }
VOID ReleaseSemaphore(struct SignalSemaphore *sem) { (VOID)sem; }
VOID Forbid(VOID) { }
VOID Permit(VOID) { }

APTR ami_alloc(ULONG size) { return calloc(1, (size_t)size); }
VOID ami_free(APTR p) { free(p); }

LONG bsd_fail(struct AmiSocketBase *base, LONG error)
{
    base->sb_Errno = error;
    return -1;
}

AmiSocket *bsd_lookup(struct AmiSocketBase *base, LONG fd)
{
    if (fd < 0 || fd >= base->sb_TableSize)
        return NULL;
    return base->sb_Table[fd];
}

LONG bsd_fd_alloc(struct AmiSocketBase *base, AmiSocket *sock)
{
    LONG fd;

    for (fd = 0; fd < base->sb_TableSize; fd++)
    {
        if (base->sb_Table[fd] == NULL)
        {
            base->sb_Table[fd] = sock;
            return fd;
        }
    }
    return bsd_fail(base, AMI_EMFILE);
}

LONG bsd_fd_free(struct AmiSocketBase *base, LONG fd)
{
    if (fd < 0 || fd >= base->sb_TableSize)
        return bsd_fail(base, AMI_EBADF);
    base->sb_Table[fd] = NULL;
    return 0;
}

VOID bsd_socket_retain(AmiSocket *sock) { sock->as_RefCount++; }
/* socket.c's release, whose owner decision is the shared bsd_owner_drop(). */
VOID bsd_socket_release(struct AmiSocketBase *base, AmiSocket *sock)
{
    if (sock->as_RefCount != 0)
        sock->as_RefCount--;
    if (sock->as_RefCount != 0)
        bsd_owner_drop(base, sock);
}

LONG bsd_nx_enter(struct AmiSocketBase *base) { (VOID)base; return 0; }
VOID bsd_nx_leave(struct AmiSocketBase *base) { (VOID)base; }

static VOID reset_fixture(AmiSocket *sock)
{
    /* A previous case may have intentionally left a handoff parked.  Its
       socket was stack-owned by that case, so discard only the registry
       entries before replacing the fixture; never dereference that socket. */
    while (bsd_handoff_pending(&master_base))
        ami_free(RemHead((struct List *)&master_base.sb_Handoffs));

    memset(tables, 0, sizeof(tables));
    memset(&master_base, 0, sizeof(master_base));
    memset(&source_base, 0, sizeof(source_base));
    memset(&target_base, 0, sizeof(target_base));
    memset(&third_base, 0, sizeof(third_base));
    memset(sock, 0, sizeof(*sock));

    master_base.sb_Table = tables[0];
    source_base.sb_Table = tables[1];
    target_base.sb_Table = tables[2];
    master_base.sb_TableSize = source_base.sb_TableSize =
        target_base.sb_TableSize = 4;
    source_base.sb_Master = target_base.sb_Master = &master_base;
    bsd_handoff_init(&master_base);

    sock->as_Flags = ASF_TCP | ASF_LISTENING;
    sock->as_Domain = AF_INET;
    sock->as_Type = SOCK_STREAM;
    sock->as_Protocol = IPPROTO_TCP;
    sock->as_RefCount = 1;
    sock->as_Owner = &source_base;
    source_base.sb_Table[0] = sock;
}

static VOID test_release_listener(VOID)
{
    AmiSocket sock;
    LONG id;
    LONG fd;

    reset_fixture(&sock);
    id = bsd_ReleaseSocket(0, UNIQUE_ID, &source_base);
    CHECK(id > 65535, "ReleaseSocket accepts a listening descriptor");
    CHECK(source_base.sb_Table[0] == NULL,
          "and detaches it from the releasing descriptor table");
    CHECK(sock.as_Owner == NULL, "the parked listener has no stale owner");

    fd = bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, 0, &target_base);
    CHECK(fd == 0, "the listener can be obtained by another base");
    CHECK(target_base.sb_Table[0] == &sock,
          "the obtained descriptor names the same listener");
    CHECK(sock.as_Owner == &target_base,
          "future accept events signal the obtaining base");
    CHECK((sock.as_Flags & ASF_LISTENING) != 0,
          "the listen state survives the handoff");
}

/*
 * F-057: a Dup2Socket() alias in the same base keeps the base as the owner
 * when another descriptor of the socket goes, by close or by ReleaseSocket().
 */
static VOID test_alias_keeps_owner(VOID)
{
    AmiSocket sock;
    LONG id;

    /* close(fd 0) with fd 1 an alias: the close path frees, then releases. */
    reset_fixture(&sock);
    source_base.sb_Table[1] = &sock;
    sock.as_RefCount = 2;
    CHECK(bsd_fd_free(&source_base, 0) == 0, "fd 0 is freed");
    bsd_socket_release(&source_base, &sock);
    CHECK(sock.as_RefCount == 1, "one reference is left");
    CHECK(sock.as_Owner == &source_base,
          "the surviving alias keeps its base as the owner after a close");

    /* The last alias goes with another reference elsewhere: the owner goes. */
    sock.as_RefCount = 2;
    CHECK(bsd_fd_free(&source_base, 1) == 0, "fd 1 is freed");
    bsd_socket_release(&source_base, &sock);
    CHECK(sock.as_Owner == NULL,
          "with no alias left the base stops being the owner");

    /* ReleaseSocket() of one alias parks it, and the other still signals. */
    reset_fixture(&sock);
    source_base.sb_Table[1] = &sock;
    sock.as_RefCount = 2;
    id = bsd_ReleaseSocket(0, UNIQUE_ID, &source_base);
    CHECK(id > 65535, "ReleaseSocket accepts an aliased descriptor");
    CHECK(source_base.sb_Table[0] == NULL && source_base.sb_Table[1] == &sock,
          "only the released descriptor is detached");
    CHECK(sock.as_Owner == &source_base,
          "the surviving alias keeps its base as the owner after ReleaseSocket");

    /* Another base's ownership is never cleared by this one. */
    reset_fixture(&sock);
    sock.as_Owner = &target_base;
    source_base.sb_Table[0] = NULL;
    bsd_owner_drop(&source_base, &sock);
    CHECK(sock.as_Owner == &target_base, "another base's ownership is left alone");
}

/*
 * F-043: the socket passes to another opener still holding it.  A copies a
 * listener out with ReleaseCopyOfSocket() and keeps its descriptor; B obtains
 * the copy and owns it.  When B's descriptor goes, A must own it again, and be
 * told once, or its descriptor has no stack and no signals.  The bases sit on
 * the master's sb_Children as bsd_child_create() leaves them.
 */
static VOID link_children(VOID)
{
    struct List *l = (struct List *)&master_base.sb_Children;

    l->lh_Head     = (struct Node *)&l->lh_Tail;
    l->lh_Tail     = NULL;
    l->lh_TailPred = (struct Node *)&l->lh_Head;
    AddTail(l, (struct Node *)&source_base.sb_Node);
    AddTail(l, (struct Node *)&target_base.sb_Node);
    AddTail(l, (struct Node *)&third_base.sb_Node);

    memset(&third_base, 0, offsetof(struct AmiSocketBase, sb_Node));
    third_base.sb_Table = tables[3];
    third_base.sb_TableSize = 4;
    third_base.sb_Master = &master_base;

    source_base.sb_Task = &task_a;
    target_base.sb_Task = &task_b;
    third_base.sb_Task  = &task_c;
    source_base.sb_EventSigMask = 1UL << 10;
    target_base.sb_EventSigMask = 1UL << 11;
    third_base.sb_EventSigMask  = 1UL << 12;
    signals = 0;
    signalled_task = NULL;
}

/* A descriptor of `base` goes, the way the close path takes it. */
static VOID close_fd(struct AmiSocketBase *base, LONG fd, AmiSocket *sock)
{
    CHECK(bsd_fd_free(base, fd) == 0, "the descriptor is freed");
    bsd_socket_release(base, sock);
}

static VOID test_owner_reelect(VOID)
{
    AmiSocket sock;
    LONG id;
    LONG fd;

    /* Two bases: A copies, B obtains and closes. */
    reset_fixture(&sock);
    memset(tables[3], 0, sizeof(tables[3]));
    link_children();
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    fd = bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP, &target_base);
    CHECK(fd == 0 && sock.as_Owner == &target_base,
          "the obtaining base owns the copy, as before");
    close_fd(&target_base, fd, &sock);
    CHECK(sock.as_RefCount == 1, "A's reference is left");
    CHECK(sock.as_Owner == &source_base,
          "A, still holding it, owns it again");
    CHECK(signals == 1 && signalled_task == &task_a &&
              signalled_mask == source_base.sb_EventSigMask,
          "and is signalled once for what it missed");

    /* Three bases: A holds, B and C obtain copies; the owner closes each
       time, and the socket always lands on a base that still holds it. */
    reset_fixture(&sock);
    memset(tables[3], 0, sizeof(tables[3]));
    link_children();
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    CHECK(bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &target_base) == 0, "B obtains a copy");
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    CHECK(bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &third_base) == 0, "C obtains another");
    CHECK(sock.as_Owner == &third_base && sock.as_RefCount == 3,
          "C owns it, three references");
    close_fd(&third_base, 0, &sock);
    CHECK(sock.as_Owner == &source_base, "C goes: the first holder, A");
    close_fd(&source_base, 0, &sock);
    CHECK(sock.as_Owner == &target_base, "A goes: B, the last holder");
    CHECK(sock.as_RefCount == 1, "one reference left");

    /* A holder whose Task is gone is the owner only if no live one holds. */
    reset_fixture(&sock);
    memset(tables[3], 0, sizeof(tables[3]));
    link_children();
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    CHECK(bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &target_base) == 0, "B obtains a copy");
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    CHECK(bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &third_base) == 0, "C obtains another");
    source_base.sb_Task = NULL;             /* A's Task died */
    signals = 0;
    close_fd(&third_base, 0, &sock);
    CHECK(sock.as_Owner == &target_base, "a live holder is preferred");
    close_fd(&target_base, 0, &sock);
    CHECK(sock.as_Owner == &source_base, "the dead one when it is the only one");
    CHECK(signals == 1, "and nobody signals a Task that is gone");

    /* Nobody else holds it: NULL, as before. */
    reset_fixture(&sock);
    memset(tables[3], 0, sizeof(tables[3]));
    link_children();
    id = bsd_ReleaseSocket(0, UNIQUE_ID, &source_base);
    CHECK(sock.as_Owner == NULL, "a fully released socket belongs to nobody");
    CHECK(signals == 0, "and nobody is signalled");
}

static VOID test_release_copy_listener(VOID)
{
    AmiSocket sock;
    LONG id;
    LONG fd;

    reset_fixture(&sock);
    id = bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base);
    CHECK(id > 65535, "ReleaseCopyOfSocket accepts a listening descriptor");
    CHECK(source_base.sb_Table[0] == &sock,
          "and leaves the original descriptor installed");
    CHECK(sock.as_RefCount == 2, "the parked copy owns a second reference");

    fd = bsd_ObtainSocket(id, AF_INET, SOCK_STREAM, IPPROTO_TCP, &target_base);
    CHECK(fd == 0 && target_base.sb_Table[0] == &sock,
          "the copied listener can be obtained");
    CHECK((sock.as_Flags & ASF_LISTENING) != 0,
          "and remains a listener after the copy handoff");
}

/* The last opener's close: bsd_handoff_take() moves the registry off the
   master under sb_Lock, bsd_handoff_flush() releases it afterwards. */
static VOID test_take_and_flush(VOID)
{
    AmiSocket      sock;
    struct MinList moved;
    struct MinNode *first;
    struct MinNode *second;

    reset_fixture(&sock);
    CHECK(bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base) > 65535 &&
              bsd_ReleaseCopyOfSocket(0, UNIQUE_ID, &source_base) > 65535,
          "two entries are parked");
    CHECK(sock.as_RefCount == 3, "each holding a reference");

    bsd_handoff_take(&master_base, &moved);
    CHECK(!bsd_handoff_pending(&master_base), "the master registry is empty");
    CHECK(master_base.sb_Handoffs.mlh_Head ==
                  (struct MinNode *)&master_base.sb_Handoffs.mlh_Tail &&
              master_base.sb_Handoffs.mlh_TailPred ==
                  (struct MinNode *)&master_base.sb_Handoffs.mlh_Head,
          "and a well-formed empty list");

    first  = moved.mlh_Head;
    second = first->mln_Succ;
    CHECK(first->mln_Pred == (struct MinNode *)&moved.mlh_Head,
          "the first moved entry points back at the new list head");
    CHECK(second->mln_Pred == first && moved.mlh_TailPred == second,
          "the second is the tail");
    CHECK(second->mln_Succ == (struct MinNode *)&moved.mlh_Tail &&
              moved.mlh_Tail == NULL,
          "and ends at the new list's tail");

    bsd_handoff_flush(&master_base, &moved, TRUE);
    CHECK(sock.as_RefCount == 1, "the flush released both references");
    CHECK(moved.mlh_Head == (struct MinNode *)&moved.mlh_Tail,
          "and emptied the moved list");
    CHECK(source_base.sb_Table[0] == &sock, "the original stays installed");
}

int main(void)
{
    test_release_listener();
    test_release_copy_listener();
    test_alias_keeps_owner();
    test_owner_reelect();
    test_take_and_flush();
    printf("handoff: %lu checks, %lu failures\n", checks, failures);
    return failures ? 1 : 0;
}
