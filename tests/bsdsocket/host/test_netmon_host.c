/*
 * netmonitor.c on the host: the dead-task sweep detaches a dead owner's
 * monitor hooks without waiting (F-050).
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"
#include "netmonitor.h"

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

static struct AmiSocketBase dead_base;
static struct AmiSocketBase live_base;
static struct Task          me_task;

static long allocs;
static long frees;
static long waits;

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

VOID Forbid(VOID) { }
VOID Permit(VOID) { }
struct Task *FindTask(const char *name) { (VOID)name; return &me_task; }
VOID Signal(struct Task *task, ULONG mask) { (VOID)task; (VOID)mask; }
ULONG Wait(ULONG mask) { waits++; return mask; }

APTR AllocMem(ULONG size, ULONG req)
{
    (VOID)req;
    allocs++;
    return calloc(1, (size_t)size);
}

VOID FreeMem(APTR block, ULONG size)
{
    (VOID)size;
    frees++;
    memset(block, 0x5A, (size_t)size);
    free(block);
}

LONG bsd_fail(struct AmiSocketBase *base, LONG code)
{
    base->sb_Errno = code;
    return -1;
}

/* The hooks.  One of them runs the sweep while it is being called. */
static long calls_a;
static long calls_b;
static long calls_live;
static int  sweep_inside;

static ULONG hook_a_fn(struct Hook *hook, APTR reserved, APTR message)
{
    (VOID)hook; (VOID)reserved; (VOID)message;
    calls_a++;
    if (sweep_inside)
    {
        long before = frees;

        bsd_netmon_detach_owner(&dead_base);
        CHECK(frees == before,
              "a registration a dispatch is inside is not freed under it");
    }
    return 0;
}

static ULONG hook_b_fn(struct Hook *hook, APTR reserved, APTR message)
{
    (VOID)hook; (VOID)reserved; (VOID)message;
    calls_b++;
    return 0;
}

static ULONG hook_live_fn(struct Hook *hook, APTR reserved, APTR message)
{
    (VOID)hook; (VOID)reserved; (VOID)message;
    calls_live++;
    return 0;
}

static struct Hook hook_a;
static struct Hook hook_b;
static struct Hook hook_live;

typedef union HookEntry
{
    ULONG (*raw)(VOID);
    ULONG (*callback)(struct Hook *, APTR, APTR);
} HookEntry;

static VOID setup(VOID)
{
    HookEntry entry;

    memset(&hook_a, 0, sizeof(hook_a));
    memset(&hook_b, 0, sizeof(hook_b));
    memset(&hook_live, 0, sizeof(hook_live));
    entry.callback = hook_a_fn;
    hook_a.h_Entry = entry.raw;
    entry.callback = hook_b_fn;
    hook_b.h_Entry = entry.raw;
    entry.callback = hook_live_fn;
    hook_live.h_Entry = entry.raw;
    calls_a = calls_b = calls_live = 0;
}

static VOID test_idle_detach(VOID)
{
    setup();
    allocs = frees = 0;

    CHECK(bsd_AddNetMonitorHookTagList(MHT_Connect, &hook_a, NULL, &dead_base) == 0,
          "the dead owner's first hook installs");
    CHECK(bsd_AddNetMonitorHookTagList(MHT_Bind, &hook_b, NULL, &dead_base) == 0,
          "and its second, on another list");
    CHECK(bsd_AddNetMonitorHookTagList(MHT_Connect, &hook_live, NULL, &live_base) == 0,
          "a live owner's hook installs");

    bsd_netmon_detach_owner(&dead_base);
    CHECK(frees == 2, "both idle registrations of the dead owner are freed");
    CHECK(waits == 0, "without waiting");
    CHECK(bsd_netmon_busy(), "the live owner's hook is still installed");

    (VOID)bsd_netmon_dispatch(MHT_Connect, NULL);
    (VOID)bsd_netmon_dispatch(MHT_Bind, NULL);
    CHECK(calls_a == 0 && calls_b == 0, "no later dispatch reaches a dead owner's hook");
    CHECK(calls_live == 1, "the live owner's hook still runs");

    /* Ordinary Remove semantics are unchanged. */
    bsd_RemoveNetMonitorHook(&hook_live, &live_base);
    CHECK(!bsd_netmon_busy(), "RemoveNetMonitorHook still removes");
    CHECK(frees == 3, "and frees");

    /* Nothing of the dead owner's left: a second detach does nothing. */
    bsd_netmon_detach_owner(&dead_base);
    CHECK(frees == 3, "a second detach frees nothing");
}

static VOID test_detach_in_flight(VOID)
{
    setup();
    allocs = frees = 0;

    CHECK(bsd_AddNetMonitorHookTagList(MHT_Connect, &hook_a, NULL, &dead_base) == 0,
          "the dead owner's hook installs");
    sweep_inside = 1;
    (VOID)bsd_netmon_dispatch(MHT_Connect, NULL);
    sweep_inside = 0;
    CHECK(calls_a == 1, "the call in flight completes");
    CHECK(frees == 1, "the dispatch frees the registration when the call returns");
    CHECK(waits == 0, "nothing waited");
    CHECK(!bsd_netmon_busy(), "nothing is left installed");

    (VOID)bsd_netmon_dispatch(MHT_Connect, NULL);
    CHECK(calls_a == 1, "and it is not called again");
}

int main(void)
{
    dead_base.sb_EventSigMask = 0x100;
    live_base.sb_EventSigMask = 0x200;

    test_idle_detach();
    test_detach_in_flight();
    printf("netmon: %lu checks, %lu failures\n", checks, failures);
    return failures ? 1 : 0;
}
