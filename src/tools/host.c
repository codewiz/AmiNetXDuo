/*
 * host, resolve a name the way this machine's own programs would.
 *
 *     host NAME/A,TIMEOUT/N/K,IPV4=-4/S,IPV6=-6/S
 * SPDX-License-Identifier: MIT
 */

#include "toolsock.h"
#include "aminetxduo/version.h"

#include <exec/io.h>
#include <devices/timer.h>

const char *const tool_name = "host";

static const char version_tag[] __attribute__((used)) =
    TOOL_VERSTAG("host");

#define TEMPLATE    "NAME/A,TIMEOUT/N/K,IPV4=-4/S,IPV6=-6/S"

enum
{
    ARG_NAME = 0,
    ARG_TIMEOUT,
    ARG_IPV4,
    ARG_IPV6,
    ARG_COUNT
};

#define HOST_DEFAULT_TIMEOUT    10UL        /* seconds */
#define HOST_NAME_MAX           256

/*
 * TIMEOUT (F-199).  The lookup is bsdsocket.library's, one synchronous call,
 * so the deadline is a timer.device signal added to the break mask the
 * library's resolver polls between the rungs of its retry ladder, as it polls
 * Ctrl-C.  A rung is one synchronous query to every configured server, up to
 * two seconds each, so the answer comes by TIMEOUT plus at most one rung, not
 * to the second; and the library gives up on its own after 30 seconds, so a
 * longer TIMEOUT is that.  Nothing is left running: the rung has returned
 * before the signal is looked at.
 */
typedef struct HostDeadline
{
    struct MsgPort     *port;
    struct timerequest *req;
    BOOL                open;
    BOOL                armed;
} HostDeadline;

static BOOL host_deadline_arm(HostDeadline *d, ULONG seconds)
{
    d->port  = CreateMsgPort();
    d->req   = NULL;
    d->open  = FALSE;
    d->armed = FALSE;

    if (d->port == NULL)
        return FALSE;

    d->req = (struct timerequest *)
             CreateIORequest(d->port, (ULONG)sizeof(*d->req));
    if (d->req == NULL)
        return FALSE;

    if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_VBLANK,
                   (struct IORequest *)d->req, 0) != 0)
        return FALSE;
    d->open = TRUE;

    d->req->tr_node.io_Command = TR_ADDREQUEST;
    d->req->tr_time.tv_secs    = seconds;
    d->req->tr_time.tv_micro   = 0;
    SendIO((struct IORequest *)d->req);
    d->armed = TRUE;

    return TRUE;
}

static ULONG host_deadline_mask(const HostDeadline *d)
{
    return (d->armed && d->port != NULL) ? (1UL << d->port->mp_SigBit) : 0UL;
}

static BOOL host_deadline_passed(const HostDeadline *d)
{
    return (BOOL)(d->armed &&
                  CheckIO((struct IORequest *)d->req) != NULL);
}

/* The deadline is claimed only where the library was told of it: a base
   that refused the mask was bounded by its own 30 seconds, not by this. */
static BOOL host_late(const HostDeadline *d, BOOL enforced)
{
    return (BOOL)(enforced && host_deadline_passed(d));
}

/* Every exit: the request back, the device closed, the signal cleared. */
static VOID host_deadline_close(HostDeadline *d)
{
    ULONG mask = host_deadline_mask(d);

    if (d->armed)
    {
        if (CheckIO((struct IORequest *)d->req) == NULL)
            AbortIO((struct IORequest *)d->req);
        WaitIO((struct IORequest *)d->req);
        d->armed = FALSE;
    }
    if (d->open)
        CloseDevice((struct IORequest *)d->req);
    if (d->req != NULL)
        DeleteIORequest((struct IORequest *)d->req);
    if (d->port != NULL)
        DeleteMsgPort(d->port);
    if (mask != 0)
        SetSignal(0UL, mask);

    d->port = NULL;
    d->req  = NULL;
    d->open = FALSE;
}

int main(int argc, char **argv)
{
    LONG            args[ARG_COUNT];
    struct RDArgs  *rda;
    struct Library *sbase;
    const char     *name;
    ULONG           addr = 0;
    LONG            family;
    BOOL            ok;
    BOOL            no_family = FALSE;
    char            text[HOST_NAME_MAX];
    ToolAddrInfo    hints;
    ToolAddrInfo   *list = NULL;
    ULONG           v6[4];
    ULONG           timeout = HOST_DEFAULT_TIMEOUT;
    ULONG           old_mask = SIGBREAKF_CTRL_C;
    BOOL            mask_set = FALSE;
    BOOL            late = FALSE;
    BOOL            enforced = FALSE;   /* the path taken was really told */
    HostDeadline    deadline;
    int             rc;

    (VOID)argv;

    if (tool_from_workbench(argc))
        return RETURN_FAIL;

    tool_break_arm();

    args[ARG_NAME]    = 0;
    args[ARG_TIMEOUT] = 0;
    args[ARG_IPV4]    = 0;
    args[ARG_IPV6]    = 0;

    rda = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    if (rda == NULL)
    {
        tool_fault(IoErr());
        return RETURN_ERROR;
    }

    name = (const char *)args[ARG_NAME];

    /* 0, like no TIMEOUT at all, is the default. */
    if (args[ARG_TIMEOUT] != 0)
    {
        LONG seconds = *(const LONG *)args[ARG_TIMEOUT];

        if (seconds < 0)
        {
            tool_error("TIMEOUT cannot be negative");
            FreeArgs(rda);
            return RETURN_ERROR;
        }
        if (seconds > 0)
            timeout = (ULONG)seconds;
    }

    if (!tool_arg_family(args[ARG_IPV4], args[ARG_IPV6], &family))
    {
        FreeArgs(rda);
        return RETURN_ERROR;
    }

    if (tool_parse_ip6(name, v6))
    {
        tool_error("\"%s\" is an address, not a name", (LONG)name);
        tool_printf("  nslookup asks the DNS for its ip6.arpa record.\n");
        FreeArgs(rda);
        return RETURN_ERROR;
    }

    /* A dotted quad is looked up backwards, and an address already says which
       family it is. -6 over one contradicts the argument. */
    if (family == TOOL_AF_INET6 && ami_config_parse_ip(name, &addr))
    {
        tool_error("%s is an IPv4 address, and -6 was given", (LONG)name);
        FreeArgs(rda);
        return RETURN_ERROR;
    }

    /*
     * Starts the stack if nothing else has, and is closed again below like
     * every other client command closes its own. Leaving it open cost one
     * cloned AmiSocketBase, 2568 bytes, on every single run.
     */
    sbase = tool_socket_open();
    if (sbase == NULL)
    {
        FreeArgs(rda);
        return RETURN_FAIL;
    }

    /* Same as tool_sock_resolve_af(): -6 on a machine with no IPv6 is a fact
       about the machine, not about the name. */
    if (family == TOOL_AF_INET6 && !tool_sock_have_ipv6(sbase))
    {
        tool_error("%s: this machine's network has no IPv6", (LONG)name);
        tool_no_ipv6_note();
        CloseLibrary(sbase);
        FreeArgs(rda);
        return RETURN_ERROR;
    }

    /* All three ways of asking below obey it: the base this command opened,
       and the ones tool_stack_lookup() and tool_stack_lookup_addr() open. */
    if (host_deadline_arm(&deadline, timeout))
    {
        tool_stack_break_extra(host_deadline_mask(&deadline));
        mask_set = tool_sock_breakmask(sbase, SIGBREAKF_CTRL_C |
                                       host_deadline_mask(&deadline),
                                       &old_mask);
    }
    else
    {
        tool_error("timer.device did not open, so TIMEOUT cannot be kept; "
                   "the library's own 30 seconds apply");
    }

    if (ami_config_parse_ip(name, &addr))
    {
        ok = tool_stack_lookup_addr(addr, text, sizeof(text));
        enforced = tool_stack_break_armed();
        if (ok)
            tool_printf("%s is %s\n", (LONG)name, (LONG)text);
        else if (!host_late(&deadline, enforced))
            tool_error("no name for %s", (LONG)name);
    }
    else if (tool_sock_have_addrinfo(sbase))
    {
        hints.ai_flags     = 0;
        hints.ai_family    = family;
        hints.ai_socktype  = TOOL_SOCK_STREAM;
        hints.ai_protocol  = 0;
        hints.ai_addrlen   = 0;
        hints.ai_addr      = NULL;
        hints.ai_canonname = NULL;
        hints.ai_next      = NULL;

        ok = FALSE;

        enforced = mask_set;

        if (tool_sock_getaddrinfo(sbase, name, NULL, &hints, &list) == 0)
        {
            ToolAddrInfo *ai;

            for (ai = list; ai != NULL; ai = ai->ai_next)
            {
                ToolAddr found;

                if (ai->ai_addr == NULL ||
                    !tool_sock_addr_get(ai->ai_addr, &found))
                    continue;

                tool_addr_text(sbase, &found, text, sizeof(text));
                tool_printf("%s has %saddress %s\n", (LONG)name,
                            (LONG)(TOOL_ADDR_IS6(&found) ? "IPv6 " : ""),
                            (LONG)text);
                ok = TRUE;
            }

            tool_sock_freeaddrinfo(sbase, list);
        }

        if (!ok && !host_late(&deadline, enforced) &&
            tool_sock_family_absent(sbase, name, family))
        {
            tool_sock_say_no_family(name, family);
            no_family = TRUE;
        }
        else if (!ok)
        {
            if (!host_late(&deadline, enforced))
                tool_error("cannot resolve \"%s\"", (LONG)name);
        }
    }
    else if (family == TOOL_AF_INET6)
    {
        /* gethostbyname() answers with an A and nothing else, so there is no
           way to ask this library for the AAAA. */
        ok = FALSE;
        tool_error("this bsdsocket.library has no getaddrinfo, so -6 cannot "
                   "be answered");
        no_family = TRUE;
    }
    else
    {
        ok = tool_stack_lookup(name, &addr);
        enforced = tool_stack_break_armed();
        if (ok)
        {
            ami_config_format_ip(addr, text, sizeof(text));
            tool_printf("%s has address %s\n", (LONG)name, (LONG)text);
        }
        else
        {
            if (!host_late(&deadline, enforced))
                tool_error("cannot resolve \"%s\"", (LONG)name);
        }
    }

    late = (BOOL)(!ok && host_late(&deadline, enforced));

    tool_stack_break_extra(0UL);
    if (mask_set)
        (VOID)tool_sock_breakmask(sbase, old_mask, NULL);
    host_deadline_close(&deadline);

    rc = ok ? RETURN_OK : RETURN_ERROR;

    if (tool_break())
    {
        tool_fault(ERROR_BREAK);
        rc = RETURN_WARN;
    }
    else if (late)
    {
        tool_error("%s: no answer within %lu seconds", (LONG)name, timeout);
    }
    else if (!ok && !no_family)
    {
        /*
         * gethostbyname() fails without a reason a command can read, and the
         * two candidates need opposite actions from the user, so print both.
         * nslookup tells them apart.
         */
        tool_explain_resolve(name, AMI_NET_ERR_NONAME);
    }

    CloseLibrary(sbase);
    FreeArgs(rda);
    return rc;
}
