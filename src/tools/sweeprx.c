/* SweepRx: temporary per-interface TCP receive tuning. SPDX-License-Identifier: MIT */
#include "iperfcore.h"
#include "rxsweep.h"
#include <sys/types.h>
#include <libraries/bsdsocket.h>
#include <string.h>

const char *const tool_name = "SweepRx";
static const char version_tag[] __attribute__((used)) = TOOL_VERSTAG("SweepRx");
#define TEMPLATE "INTERFACE,TO/K,PORT/K/N,TIME/K/N,REPEATS/K/N,WAIT/K/N," \
    "IPREQUESTS/K,ARPREQUESTS/K,TCPWINDOW/K,TCPACKMAX/K,TCPGROWRTT/K," \
    "RXRUNMAX/K,RXREPOST/K,DRYRUN/S,HELP/S"
enum { A_IF, A_TO, A_PORT, A_TIME, A_REPEATS, A_WAIT, A_IP, A_ARP,
       A_WINDOW, A_ACK, A_GROW, A_RUN, A_REPOST, A_DRY, A_HELP, A_COUNT };
static const char *const keys[RXSWEEP_KNOBS] = {
    "IPREQUESTS", "ARPREQUESTS", "TCPWINDOW", "TCPACKMAX", "TCPGROWRTT", "RXRUNMAX", "RXREPOST"
};
static const ULONG maxima[RXSWEEP_KNOBS] = {
    AMI_CFG_READREQUESTS_MAX, AMI_CFG_READREQUESTS_MAX, AMI_CFG_TCP_WINDOW_MAX,
    AMI_CFG_TCP_ACK_MAX, AMI_CFG_TCP_GROW_RTT_MAX, AMI_CFG_RX_RUN_MAX, AMI_CFG_RX_REPOST_MAX
};
static LONG args[A_COUNT];
static RxSweepPlan sweep;
static RxSweepResults scores;
static RxSweepList lists[RXSWEEP_KNOBS];
static struct { NetStatusHeader h; NetStatusInterface r[NX_MAX_PHYSICAL_INTERFACES]; } interfaces;
static struct { NetStatusHeader h; NetStatusRxTuning r[NX_MAX_PHYSICAL_INTERFACES]; } tuning;
static struct { NetStatusHeader h; NetStatusSocket r[256]; } sockets;
static struct { NetStatusHeader h; NetStatusIfDevice r[NX_MAX_PHYSICAL_INTERFACES]; } devices;
static NetStatusRxTuneControl control;
static NetStatusRxTuning effective;
static NetStatusInterface original, before, after;
static IperfPlan plan;
static IperfRun run;
static IperfResult result;
static UBYTE payload[IPERF_BUF_MAX];
static struct Library *sb;
static BPTR csv;
static struct MsgPort *lock_port;
static const char *ifname;
static UWORD index_if;
static ULONG wait_seconds = 30;
static BOOL cancelled;
static char recovery[300], address[16];
static char device[NETSTATUS_FILE_LEN];

static VOID pack(RxSweepValues *d, const NetRxTuneValues *s)
{
    d->v[0] = s->ip_requests; d->v[1] = s->arp_requests;
    d->v[2] = s->tcp_window; d->v[3] = s->tcp_ack_max;
    d->v[4] = s->tcp_grow_rtt; d->v[5] = s->rx_run_max; d->v[6] = s->rx_repost;
}
static VOID unpack(NetRxTuneValues *d, const RxSweepValues *s)
{
    d->ip_requests = s->v[0]; d->arp_requests = s->v[1];
    d->tcp_window = s->v[2]; d->tcp_ack_max = s->v[3];
    d->tcp_grow_rtt = s->v[4]; d->rx_run_max = s->v[5]; d->rx_repost = s->v[6];
}
static int stopped(void *ctx)
{
    (VOID)ctx;
    if (tool_break()) cancelled = TRUE;
    return cancelled;
}
static BOOL read_interface(NetStatusInterface *out)
{
    LONG i, n = tool_netstatus_query(sb, NETSTATUS_INTERFACES, &interfaces,
                    sizeof(interfaces), sizeof(NetStatusInterface));
    for (i = 0; i < n && i < NX_MAX_PHYSICAL_INTERFACES; ++i)
        if (tool_stricmp(interfaces.r[i].nsi_Name, ifname) == 0) {
            *out = interfaces.r[i]; return TRUE;
        }
    return FALSE;
}
static BOOL read_tuning(VOID)
{
    LONG i, n = tool_netstatus_query(sb, NETSTATUS_RXTUNING, &tuning,
                                    sizeof(tuning), sizeof(NetStatusRxTuning));
    for (i = 0; i < n && i < NX_MAX_PHYSICAL_INTERFACES; ++i)
        if (tuning.r[i].nrt_Index == index_if) {
            effective = tuning.r[i]; return TRUE;
        }
    return FALSE;
}
static BOOL set_state(LONG state)
{
    struct TagItem tags[2];
    LONG err = 0;
    tags[0].ti_Tag = IFC_State; tags[0].ti_Data = (ULONG)state;
    tags[1].ti_Tag = TAG_DONE; tags[1].ti_Data = 0;
    if (tool_configure_interface(sb, ifname, tags, &err) == 0) return TRUE;
    tool_error("interface state change failed (error %ld)", err);
    return FALSE;
}
/* No interface index in this selector: require all TCP clients to drain.
   The library marks armed accepts using NetX's actual peer binding, including
   IPv6. Do not infer an idle listener just from a wildcard IPv4 address. */
static int tcp_busy(void *ctx)
{
    LONG j, n;
    (VOID)ctx;
    n = tool_netstatus_query(sb, NETSTATUS_SOCKETS, &sockets, sizeof(sockets), sizeof(NetStatusSocket));
    if (n < 0 || n > 256 || sockets.h.nsh_Count < sockets.h.nsh_Available) {
        tool_error("cannot check active TCP clients");
        return -1;
    }
    for (j = 0; j < n; ++j)
        if ((sockets.r[j].nso_Flags & NETSTATUS_SOCK_TCP) &&
            sockets.r[j].nso_State != NETSTATUS_TCP_CLOSED &&
            sockets.r[j].nso_State != NETSTATUS_TCP_LISTEN &&
            sockets.r[j].nso_State != NETSTATUS_TCP_TIMED_WAIT &&
            !(sockets.r[j].nso_State == NETSTATUS_TCP_SYN_RECEIVED &&
              (sockets.r[j].nso_Flags & NETSTATUS_SOCK_ACCEPT_IDLE))) return 1;
    return 0;
}
static int change_online(void *ctx, int online)
{
    (VOID)ctx;
    return set_state(online ? SM_Online : SM_Offline) ? 0 : -1;
}
static uint32_t change_millis(void *ctx)
{
    (VOID)ctx;
    return ami_millis();
}
static void change_pause(void *ctx)
{
    (VOID)ctx;
    Delay(5);
}
static int change_write(void *ctx, const RxSweepValues *values)
{
    LONG err = 0;
    (VOID)ctx;
    memset(&control, 0, sizeof(control));
    control.nrtc_Control.nsc_Index = index_if;
    control.nrtc_Mask = NETRXTUNE_ALL;
    unpack(&control.nrtc_Values, values);
    if (!tool_netstatus_control_sized(sb, NETCTRL_INTERFACE_RXTUNING,
                    &control.nrtc_Control, sizeof(control), &err)) return 0;
    if (err == 16 /* BSD EBUSY */) return 1;
    tool_error("cannot apply receive settings (error %ld)", err);
    return -1;
}
static int apply(void *ctx, const RxSweepValues *values, int restoring)
{
    RxSweepValues got;
    static const RxSweepChangeOps change = {
        change_online, tcp_busy, change_write, stopped, change_millis, change_pause
    };
    /* Recovery gets its own longer budget, even after timeout or Ctrl-C. */
    if (rxsweep_change(&change, ctx, values, restoring,
                       restoring ? 60000UL : wait_seconds * 1000UL)) {
        tool_error("receive settings change failed or TCP drain timed out; close network clients");
        return -1;
    }
    /* Give link/driver state a second to settle, also on slow cards. */
    if (restoring) Delay(50);
    else if (tool_delay_ticks(50)) { cancelled = TRUE; return -1; }
    if (!read_interface(&before) || before.nsi_Index != index_if ||
        before.nsi_Address != original.nsi_Address ||
        (before.nsi_Flags & (NETSTATUS_IF_ONLINE | NETSTATUS_IF_LINKUP)) !=
        (NETSTATUS_IF_ONLINE | NETSTATUS_IF_LINKUP) || !read_tuning() ||
        (effective.nrt_Flags & (NETRXTUNE_RUNNING | NETRXTUNE_ONLINE)) !=
        (NETRXTUNE_RUNNING | NETRXTUNE_ONLINE)) {
        tool_error("interface address/state changed or tuning readback failed");
        return -1;
    }
    pack(&got, &effective.nrt_Requested);
    if (memcmp(&got, values, sizeof(got)) != 0) {
        tool_error("receive settings did not read back as requested"); return -1;
    }
    return 0;
}
static int measure(void *ctx, RxSweepSample *sample)
{
    ULONG started;
    LONG state = IPERF_RUNNING;
    BOOL failed = FALSE;
    (VOID)ctx;
    if (iperf_begin(&run, sb, &plan, payload) != 0) failed = TRUE;
    started = ami_millis();
    while (!failed && state == IPERF_RUNNING) {
        if (stopped(NULL) || (ami_millis() - started) >
                (wait_seconds + plan.seconds + 5) * 1000UL) {
            failed = TRUE; iperf_abort(&run); break;
        }
        state = iperf_slice(&run);
    }
    iperf_end(&run, &result); /* next apply waits ONLINE for asynchronous close */
    if (failed || state == IPERF_FAILED) {
        tool_error("receive stopped or timed out; check the peer (error %ld)", result.err);
        return -1;
    }
    if (!read_interface(&after)) return -1;
    sample->bits = result.bits;
    /* A premature EOF/reset is a completed iperf run, but not a full sweep
       trial. Never rank it, nor a trial with local receive errors/drops. */
    sample->valid = result.bits != 0 && result.ms >= plan.seconds * 1000UL &&
        after.nsi_Index == index_if && after.nsi_Address == original.nsi_Address &&
        after.nsi_RxErrors == before.nsi_RxErrors &&
        after.nsi_Overruns == before.nsi_Overruns &&
        after.nsi_AllocFailures == before.nsi_AllocFailures;
    return 0;
}
static BOOL file_printf(BPTR f, const char *fmt, ...)
{
    LONG n;
    va_list ap;
    va_start(ap, fmt);
    n = VFPrintf(f, (CONST_STRPTR)fmt, (APTR)ap);
    va_end(ap);
    return n >= 0;
}
static int record(void *ctx, int phase, unsigned candidate, unsigned repeat,
                  const RxSweepValues *values, const RxSweepSample *sample)
{
    unsigned k;
    RxSweepValues actual;
    BOOL ok;
    (VOID)ctx;
    pack(&actual, &effective.nrt_Effective);
    ok = file_printf(csv, "%ld,%lu,%lu,%lu,%lu,%lu,%lu,%lu",
          (LONG)phase, (ULONG)candidate, (ULONG)repeat + 1, (ULONG)sample->valid,
          (ULONG)sample->bits, result.ms, result.bytes_hi, result.bytes_lo);
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        ok = file_printf(csv, ",%lu", (ULONG)values->v[k]) && ok;
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        ok = file_printf(csv, ",%lu", (ULONG)actual.v[k]) && ok;
    ok = file_printf(csv, ",%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
          effective.nrt_HardwareBytes, effective.nrt_PoolTotal, effective.nrt_PoolFree,
          (ULONG)((effective.nrt_Flags & NETRXTUNE_BATCH) != 0),
          after.nsi_RxErrors - before.nsi_RxErrors,
          after.nsi_Overruns - before.nsi_Overruns,
          after.nsi_AllocFailures - before.nsi_AllocFailures) && ok;
    if (!Flush(csv)) ok = FALSE;
    tool_say("phase=%ld case=%lu repeat=%lu bits_per_sec=%lu valid=%lu\n",
          (LONG)phase, (ULONG)candidate, (ULONG)repeat + 1,
          (ULONG)sample->bits, (ULONG)sample->valid);
    if (!ok) tool_error("cannot write results; stopping and restoring settings");
    return ok ? 0 : -1;
}
static VOID print_values(const RxSweepValues *v)
{
    unsigned k;
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        tool_printf("%s%s=%lu", (LONG)(k ? " " : ""), (LONG)keys[k], (ULONG)v->v[k]);
    tool_printf("\n");
}
static BOOL write_recovery(const char *path)
{
    BPTR f;
    unsigned k, attempt;
    BOOL ok;
    if (strlen(path) + sizeof(".restore") > sizeof(recovery)) return FALSE;
    strcpy(recovery, path); strcat(recovery, ".restore");
    if (tool_exists(path) || tool_exists(recovery)) {
        tool_error("results or recovery file already exists; use another TO path"); return FALSE;
    }
    f = Open((CONST_STRPTR)recovery, MODE_NEWFILE);
    if (!f) return FALSE;
    ok = file_printf(f, "; Restore saved settings locally, with bounded ONLINE drain retries.\n"
                      "FailAt 21\nConfigureNetInterface %s ONLINE\n", (LONG)ifname);
    for (attempt = 0; attempt < 12; ++attempt) {
        ok = file_printf(f, "Wait 5 SECS\nConfigureNetInterface %s OFFLINE\n"
                           "ConfigureNetInterface %s", (LONG)ifname, (LONG)ifname) && ok;
        for (k = 0; k < RXSWEEP_KNOBS; ++k)
            ok = file_printf(f, " %s=%lu", (LONG)keys[k], (ULONG)sweep.saved.v[k]) && ok;
        ok = file_printf(f, "\nIF NOT WARN\n ConfigureNetInterface %s ONLINE\n"
                           " IF NOT WARN\n  Skip SwRxDone\n ENDIF\nENDIF\n"
                           "ConfigureNetInterface %s ONLINE\n", (LONG)ifname, (LONG)ifname) && ok;
    }
    ok = file_printf(f, "Echo \"RESTORATION FAILED; close network clients and retry.\"\n"
                       "Quit 20\nLab SwRxDone\nEcho \"Original settings restored; interface online.\"\n") && ok;
    if (!Close(f)) ok = FALSE;
    return ok;
}
static VOID help(VOID)
{
    tool_printf("SweepRx INTERFACE TO=file [TIME=10 REPEATS=3 PORT=5001 WAIT=30]\n"
                "  TCP receive sweep, run from a local Amiga Shell. Close network clients.\n"
                "  Start rx-sweep-peer.py AMIGA_IP on another machine first.\n"
                "  Lists: IPREQUESTS=0,8,16 TCPWINDOW=0,16384,65536 (defaults).\n"
                "  ARPREQUESTS, TCPACKMAX, TCPGROWRTT, RXRUNMAX, RXREPOST also accept lists.\n"
                "  Unspecified other knobs keep their current values. Zero means automatic.\n"
                "  At most 8 values per list, 64 combinations, odd REPEATS 1..9.\n"
                "  DRYRUN prints the plan without changing settings or writing files.\n"
                "  Saves TO.restore before changes; restores on completion/error/Ctrl-C.\n"
                "  Results include baseline before/after; no settings are made permanent.\n");
}
int main(int argc, char **argv)
{
    struct RDArgs *rda;
    unsigned k, i, best = RXSWEEP_CASES;
    ULONG top = 0, b0, b1;
    LONG rc = RETURN_FAIL, n;
    const char *path;
    static const RxSweepOps ops = {apply, measure, record, stopped};
    (VOID)argv;
    if (tool_from_workbench(argc)) return RETURN_FAIL;
    tool_break_arm();
    rda = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    if (!rda) { tool_fault(IoErr()); return RETURN_ERROR; }
    if (args[A_HELP]) { help(); FreeArgs(rda); return RETURN_OK; }
    ifname = (const char *)args[A_IF]; path = (const char *)args[A_TO];
    if (!ifname || (!path && !args[A_DRY])) { help(); goto done; }
    /* Recovery is an AmigaDOS script; accept only literal interface names. */
    for (i = 0; ifname[i]; ++i)
        if (!((ifname[i] >= 'a' && ifname[i] <= 'z') ||
              (ifname[i] >= 'A' && ifname[i] <= 'Z') ||
              (ifname[i] >= '0' && ifname[i] <= '9') ||
              ifname[i] == '_' || ifname[i] == '-' || ifname[i] == '.')) {
            tool_error("interface name must contain only letters, digits, dot, dash or underscore"); goto done;
        }
    iperf_plan_init(&plan);
    plan.dir = IPERF_TCP_RX; plan.blocking = 1; plan.buflen = IPERF_BUF_MAX;
    sweep.repeats = 3;
#define NUMBER(a, lo, hi, dst) do { if (args[a]) { LONG x = *(LONG *)args[a]; \
    if (x < (lo) || x > (hi)) { tool_error("numeric option out of range"); goto done; } dst = x; } } while (0)
    NUMBER(A_TIME, 1, 120, plan.seconds);
    NUMBER(A_PORT, 1, 65535, plan.port);
    NUMBER(A_REPEATS, 1, RXSWEEP_REPEATS, sweep.repeats);
    NUMBER(A_WAIT, 1, 300, wait_seconds);
#undef NUMBER
    sb = tool_netstatus_open_resident();
    if (!sb) { tool_error("AmiNetXDuo must already be running"); goto done; }
    if (!args[A_DRY]) {
        struct MsgPort *port = CreateMsgPort();
        if (!port) { tool_error("cannot allocate sweep lock"); goto done; }
        port->mp_Node.ln_Name = (char *)"AmiNetXDuo.SweepRx";
        Forbid();
        if (!FindPort((CONST_STRPTR)port->mp_Node.ln_Name)) {
            AddPort(port); lock_port = port;
        }
        Permit();
        if (!lock_port) {
            DeleteMsgPort(port); tool_error("another SweepRx is already running"); goto done;
        }
    }
    if (!read_interface(&original) || !original.nsi_Address ||
        (original.nsi_Flags & (NETSTATUS_IF_SANA2 | NETSTATUS_IF_LINKUP | NETSTATUS_IF_ONLINE)) !=
        (NETSTATUS_IF_SANA2 | NETSTATUS_IF_LINKUP | NETSTATUS_IF_ONLINE)) {
        tool_error("choose an online, up SANA-II interface with an IPv4 address"); goto done;
    }
    index_if = original.nsi_Index;
    if (!read_tuning()) { tool_error("library does not support receive tuning readback"); goto done; }
    pack(&sweep.saved, &effective.nrt_Requested);
    for (k = 0; k < RXSWEEP_KNOBS; ++k) {
        const char *s = (const char *)args[A_IP + k];
        if (!s && k == 0) s = "0,8,16";
        if (!s && k == 2) s = "0,16384,65536";
        lists[k].n = 1; lists[k].v[0] = sweep.saved.v[k];
        if (s && !rxsweep_list(s, maxima[k], &lists[k])) {
            tool_error("invalid %s list (maximum %lu, at most 8 values)", (LONG)keys[k], maxima[k]); goto done;
        }
    }
    if (!rxsweep_plan(&sweep, lists)) {
        tool_error("use odd REPEATS 1..9 and at most 64 combinations"); goto done;
    }
    ami_config_format_ip(original.nsi_Address, address, sizeof(address));
    tool_addr_v4(&plan.peer, original.nsi_Address);
    tool_printf("%s (%s): %lu candidates, %lu repeats, %lu seconds each; %lu baseline trials\n",
          (LONG)ifname, (LONG)address, (ULONG)sweep.count, (ULONG)sweep.repeats,
          plan.seconds, (ULONG)sweep.repeats * 2);
    tool_printf("Original: "); print_values(&sweep.saved);
    for (i = 0; i < sweep.count; ++i) {
        tool_printf("case=%lu ", (ULONG)i); print_values(&sweep.cases[i]);
    }
    if (args[A_DRY]) { rc = RETURN_OK; goto done; }
    /* This selector has no interface index; conservatively require all TCP
       clients to be closed. Do not silently disrupt a live Shell session. */
    if (tcp_busy(NULL)) {
        tool_error("close active TCP clients before running the sweep locally"); goto done;
    }
    strcpy(device, original.nsi_Device);
    n = tool_netstatus_query(sb, NETSTATUS_IFDEVICES, &devices, sizeof(devices), sizeof(NetStatusIfDevice));
    for (i = 0; n > 0 && i < (unsigned)n && i < NX_MAX_PHYSICAL_INTERFACES; ++i)
        if (devices.r[i].nsd_Index == index_if) {
            memcpy(device, devices.r[i].nsd_Device, sizeof(device));
            device[sizeof(device) - 1] = '\0';
            break;
        }
    if (!write_recovery(path)) { tool_error("cannot save recovery script"); goto done; }
    csv = Open((CONST_STRPTR)path, MODE_NEWFILE);
    if (!csv) { tool_fault(IoErr()); goto done; }
    if (!file_printf(csv, "# SweepRx schema=1 version=" AMINETXDUO_VERSION " interface=%s address=%s device=%s unit=%lu time=%lu repeats=%lu\n"
        "phase,case,repeat,valid,bits_per_sec,ms,bytes_hi,bytes_lo",
        (LONG)ifname, (LONG)address, (LONG)device, original.nsi_Unit,
        plan.seconds, (ULONG)sweep.repeats)) goto done;
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        if (!file_printf(csv, ",requested_%s", (LONG)keys[k])) goto done;
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        if (!file_printf(csv, ",effective_%s", (LONG)keys[k])) goto done;
    if (!file_printf(csv, ",hardware_bytes,pool_total,pool_free,batch,rx_errors,overruns,alloc_failures\n") || !Flush(csv)) goto done;
    tool_say("Listening on %s:%lu. Ctrl-C stops and restores. Recovery: Execute %s\n",
          (LONG)address, (ULONG)plan.port, (LONG)recovery);
    n = rxsweep_run(&sweep, &scores, &ops, NULL);
    if (!file_printf(csv, "# status=%s\n", (LONG)(n == -2 ? "restore_failed" :
                     n ? "aborted_restored" : "complete_restored")) || !Flush(csv)) {
        tool_error("cannot write completion marker");
        if (!n) n = -1;
    }
    if (n == -2) { tool_error("RESTORATION FAILED. Close clients, then Execute %s", (LONG)recovery); goto done; }
    tool_printf("Original receive settings restored; interface online.\n");
    if (n) goto done;
    b0 = rxsweep_median(&scores.before); b1 = rxsweep_median(&scores.after);
    tool_printf("Baseline median before=%lu after=%lu bits/sec (0 means invalid).\n", b0, b1);
    for (i = 0; i < sweep.count; ++i) {
        ULONG rate = rxsweep_median(&scores.cases[i]);
        tool_printf("case=%lu median=%lu bits/sec invalid=%lu\n",
                    (ULONG)i, rate, (ULONG)scores.cases[i].invalid);
        if (rate > top) { best = i; top = rate; }
    }
    /* Treat >10% baseline drift as inconclusive. Compare without overflow. */
    if (b0 && b1 && b0 - b0 / 10 <= b1 && b1 - b1 / 10 <= b0 &&
        best != RXSWEEP_CASES && top > b0 && top > b1) {
        tool_printf("Best measured candidate (%lu bits/sec); repeat to confirm:\n", top);
        print_values(&sweep.cases[best]);
    } else tool_printf("No stable improvement established. Keep the original settings.\n");
    rc = RETURN_OK;
done:
    if (csv && !Close(csv)) { tool_error("closing results failed"); rc = RETURN_FAIL; }
    if (lock_port) { RemPort(lock_port); DeleteMsgPort(lock_port); }
    if (sb) tool_netstatus_close(sb);
    FreeArgs(rda);
    return (int)rc;
}
