/*
 * F-029: DeleteAddrAllocMessage() on a message a worker still owns.  The
 * worker reads the message, writes the lease and the result into it and
 * replies it; a delete between BeginInterfaceConfig() and that reply freed it
 * under the worker.  Now the job is orphaned and the worker frees the message
 * instead of replying it.  A delete with no worker, and a second delete, are
 * as before.
 *
 * addralloc.c is #included.  The worker runs on this thread, driven through
 * the stubs below: a DHCP state that a test can use to delete the message
 * mid-flight, and an allocator that poisons what it frees so a write after
 * the free shows.
 *
 * SPDX-License-Identifier: MIT
 */

#include "bsdsocket_vectors.h"

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

#define H_POISON    0xA5

static struct Process    h_proc;
static struct Message   *h_posted;
static int               h_replies;
static int               h_replied_freed;
static int               h_polls;
static int               h_delete_at_poll;
static int               h_delete_twice;
static struct AddressAllocationMessage *h_aam;
static ULONG             h_aam_size;
static int               h_aam_frees;
static int               h_forbid;

/* ---- exec and dos ---- */

VOID Forbid(VOID) { h_forbid++; }
VOID Permit(VOID) { h_forbid--; }
struct Task *FindTask(const char *name) { (void)name; return &h_proc.pr_Task; }
VOID PutMsg(struct MsgPort *port, struct Message *m) { (void)port; h_posted = m; }
struct MsgPort *WaitPort(struct MsgPort *port) { return port; }
struct Message *GetMsg(struct MsgPort *port)
{
    struct Message *m = h_posted;

    (void)port;
    h_posted = NULL;
    return m;
}
LONG Delay(ULONG ticks) { (void)ticks; return 0; }
struct Process *CreateNewProc(const struct TagItem *tags) { (void)tags; return &h_proc; }

static int h_is_freed(const void *p, ULONG size)
{
    const unsigned char *b = (const unsigned char *)p;
    ULONG i;

    for (i = 0; i < size; i++)
        if (b[i] != H_POISON)
            return 0;
    return 1;
}

VOID ReplyMsg(struct Message *m)
{
    h_replies++;
    if ((void *)m == (void *)h_aam && h_aam_frees > 0)
        h_replied_freed++;
}

/* ---- the allocator: a free is poisoned and kept, never reused ---- */

APTR ami_alloc_tagged(ULONG size, const char *site)
{
    (void)site;
    return calloc(1, size);
}

#ifndef ami_alloc
APTR ami_alloc(ULONG size) { return calloc(1, size); }
#endif

VOID ami_free(APTR p)
{
    if (p == NULL)
        return;
    if (p == (APTR)h_aam)
    {
        h_aam_frees++;
        memset(p, H_POISON, h_aam_size);
        return;                         /* kept, so a late write shows */
    }
    free(p);
}

/* ---- the netstack ---- */

LONG netstack_interface_dhcp_start_lease(UWORD index, ULONG addr, ULONG lease)
{ (void)index; (void)addr; (void)lease; return AMI_NET_OK; }

LONG netstack_interface_dhcp_state(UWORD index)
{
    (void)index;
    h_polls++;
    if (h_polls == h_delete_at_poll)
    {
        bsd_DeleteAddrAllocMessage(h_aam, NULL);
        if (h_delete_twice)
            bsd_DeleteAddrAllocMessage(h_aam, NULL);
    }
    return (h_polls >= 3) ? AMI_DHCP_BOUND : AMI_DHCP_WORKING;
}

LONG netstack_interface_dhcp_lease(UWORD index, AmiDhcpLease *out)
{
    (void)index;
    memset(out, 0, sizeof(*out));
    return AMI_NET_OK;
}

LONG netstack_interface_dhcp_stop(UWORD index, BOOL release)
{ (void)index; (void)release; return AMI_NET_OK; }

VOID netstack_interface_release(UWORD index) { (void)index; }

/* bsd_aam_store_lease()'s helpers. */
VOID bsd_strncpy(char *dst, const char *src, ULONG size)
{
    if (size == 0)
        return;
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

VOID DateStamp(struct DateStamp *ds) { (void)ds; }
VOID bsd_stack_transient_release(struct AmiSocketBase *base) { (void)base; }

#include "addralloc.c"

/* A message as CreateAddrAllocMessageA() leaves it, and a job running it. */
static void h_start(void)
{
    h_aam_size = (ULONG)sizeof(*h_aam);
    h_aam = (struct AddressAllocationMessage *)calloc(1, h_aam_size);
    h_aam->aam_Reserved = BSD_AAM_COOKIE;
    h_aam->aam_Version  = AAM_VERSION;
    h_aam->aam_Timeout  = AAM_TIMEOUT_MIN;
    h_aam->aam_Message.mn_ReplyPort = &h_proc.pr_MsgPort;
    h_aam_frees = 0;
    h_replies = 0;
    h_replied_freed = 0;
    h_polls = 0;
    h_delete_at_poll = 0;
    h_delete_twice = 0;
    memset(bsd_aam_jobs, 0, sizeof(bsd_aam_jobs));
    bsd_aam_workers = 0;
    h_proc.pr_Task.tc_Node.ln_Type = NT_PROCESS;

    bsd_aam_launch(h_aam, 0, NULL);
}

int main(void)
{
    /* Deleted by the caller while the worker is polling: not freed under it,
       not replied, freed once by the worker, nothing written after. */
    h_start();
    h_delete_at_poll = 1;
    bsd_aam_worker();
    CHECK(h_aam_frees == 1, "an in-flight message is freed exactly once");
    CHECK(h_replies == 0 && h_replied_freed == 0,
          "and never replied once deleted");
    CHECK(h_is_freed(h_aam, h_aam_size),
          "and nothing wrote into it after the free");
    CHECK(h_polls == 1, "the worker stopped before polling again");
    CHECK(bsd_aam_workers == 0 && bsd_aam_jobs[0] == NULL,
          "and left no job behind");

    /* Deleted twice in flight: the second finds no cookie, as before. */
    h_start();
    h_delete_at_poll = 1;
    h_delete_twice = 1;
    bsd_aam_worker();
    CHECK(h_aam_frees == 1, "a double delete in flight frees once");

    /* No delete: replied, not freed, as before. */
    h_start();
    bsd_aam_worker();
    CHECK(h_replies == 1 && h_aam_frees == 0, "a kept message is replied");
    CHECK(h_aam->aam_Result == AAMR_Success, "with its result");

    /* Deleted after the reply: freed at once, and a second delete is
       harmless. */
    bsd_DeleteAddrAllocMessage(h_aam, NULL);
    CHECK(h_aam_frees == 1, "a replied message is freed by the delete");
    bsd_DeleteAddrAllocMessage(h_aam, NULL);
    CHECK(h_aam_frees == 1, "and a second delete finds no cookie");

    /* The worker exits inside Forbid(), once per run; nothing else leaks. */
    CHECK(h_forbid == 3, "Forbid balanced but for the three workers' exits");

    printf("aam_delete: %lu checks, %lu failures\n", h_checks, h_failures);
    return (h_failures != 0) ? 1 : 0;
}
