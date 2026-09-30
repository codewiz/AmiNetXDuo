/*
 * F-042: bsd_nx_enter()'s nesting counter is the library base's, and the
 * ThreadX bracket it stands for is one Task's.  A second Task reaching the
 * same base while the holder is inside must not nest on it: it would run NetX
 * with no TX_THREAD and no baton, and its leave could end the holder's
 * bracket.  It is refused, as ami_netstack_enter_cached() refuses a second
 * Task at depth 0.
 *
 * netx_call.c is #included; the netstack bracket below counts what it is
 * asked to do, and FindTask() answers whichever Task the case is.
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"

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

static struct Task  h_task_a;
static struct Task  h_task_b;
static struct Task *h_me = &h_task_a;
static int          h_enters;
static int          h_leaves;

struct Task *FindTask(const char *name) { (void)name; return h_me; }

LONG ami_netstack_enter_cached(AmiNetCaller *caller)
{
    (void)caller;
    h_enters++;
    return AMI_NET_OK;
}

VOID ami_netstack_leave_cached(AmiNetCaller *caller)
{
    (void)caller;
    h_leaves++;
}

LONG ami_netstack_enter(AmiNetCaller *caller)
{
    return ami_netstack_enter_cached(caller);
}

VOID ami_netstack_leave(AmiNetCaller *caller)
{
    ami_netstack_leave_cached(caller);
}

VOID ami_netstack_release(AmiNetCaller *caller) { (void)caller; }
VOID bsd_error_hook_flush(struct AmiSocketBase *base) { (void)base; }

#include "netx_call.c"

int main(void)
{
    static struct AmiSocketBase base;

    /* Task A takes the bracket and nests in it, as an entry point that calls
       another does. */
    h_me = &h_task_a;
    CHECK(bsd_nx_enter(&base) == 0, "A enters");
    CHECK(bsd_nx_enter(&base) == 0, "A nests");
    CHECK(base.sb_NxNest == 2 && h_enters == 1, "one bracket, depth two");

    /* THE CASE: Task B on the same base while A is inside.  Refused: no
       depth taken, no NetX context pretended. */
    h_me = &h_task_b;
    CHECK(bsd_nx_enter(&base) != 0, "B is refused while A holds the bracket");
    CHECK(base.sb_NxNest == 2, "and takes no depth");
    CHECK(base.sb_NxTask == &h_task_a, "the bracket is still A's");

    /* A unwinds its own bracket, and only its last leave ends it. */
    h_me = &h_task_a;
    bsd_nx_leave(&base);
    CHECK(base.sb_NxNest == 1 && h_leaves == 0, "A's inner leave keeps it");
    bsd_nx_leave(&base);
    CHECK(base.sb_NxNest == 0 && h_leaves == 1 && base.sb_NxTask == NULL,
          "A's outer leave ends it");

    /* Outside any bracket, B takes the ordinary path (where
       ami_netstack_enter_cached() decides about a second Task). */
    h_me = &h_task_b;
    CHECK(bsd_nx_enter(&base) == 0 && h_enters == 2, "B enters once A is out");
    CHECK(base.sb_NxTask == &h_task_b, "and holds it");
    bsd_nx_leave(&base);
    CHECK(base.sb_NxNest == 0 && h_leaves == 2, "and leaves");

    printf("nx_nest: %lu checks, %lu failures\n", h_checks, h_failures);
    return (h_failures != 0) ? 1 : 0;
}
