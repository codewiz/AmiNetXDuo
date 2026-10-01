/*
 * AmiNetXDuo, tls.library server against tls.library client in ONE task.
 *
 * tests/tls/tls_loop.c needs two processes and a bsdsocket.library; this needs
 * neither.  The socket base handed to TLSOpen() is a fake jump table over a
 * memory pipe, and the two handshakes run as coroutines on two stacks of one
 * task, switching whenever one of them would block.  So the shipped
 * tls.library, unmodified, runs under vamos:
 *
 *   vamos -C 68000 -V libs:<dir with tls.library> -a LIBS:libs: -V pki:<dir> \
 *       build/X/tests/tls/TlsCoLoop CERT pki:leafrsa.cert.der \
 *       KEY pki:leafrsa.key.der KEYTYPE RSA STORE pki:store HOST tlsloop.test
 *
 * with the PKI tests/tls/run-tlsloop.sh generates.  An RSA key keeps the
 * server on TLS 1.2 (tls_server.c), which is the only place a ChaCha20-
 * Poly1305 TLS 1.2 record is made and opened in one run; an EC key gives
 * TLS 1.3.
 *
 * Output: coloop_* key=value lines, RESULT=PASS|FAIL last; exit 0 or 20.
 *
 * SPDX-License-Identifier: MIT
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "aminetxduo/tlslib.h"

struct Library *TLSBase;

/* ------------------------------------------------------------ coroutines -- */

asm("    .text                                  \n"
    "    .globl _co_switch                      \n"
    "_co_switch:                                \n"
    "    movem.l %d2-%d7/%a2-%a6,-(%sp)         \n"
    "    move.l  48(%sp),%a0                    \n"
    "    move.l  %sp,(%a0)                      \n"
    "    move.l  52(%sp),%sp                    \n"
    "    movem.l (%sp)+,%d2-%d7/%a2-%a6         \n"
    "    rts                                    \n");

extern __attribute__((__stkparm__)) void co_switch(ULONG *save, ULONG to);

#define CO_STACK    (64UL * 1024UL)

static ULONG    co_main_sp;
static ULONG    co_srv_sp;
static int      co_in_server;
static int      co_srv_done;
static ULONG    co_yields;

static void co_yield(void)
{
    co_yields++;
    if (co_in_server)
    {
        co_in_server = 0;
        co_switch(&co_srv_sp, co_main_sp);
    }
    else if (!co_srv_done)
    {
        co_in_server = 1;
        co_switch(&co_main_sp, co_srv_sp);
    }
}

/* ------------------------------------------------------------- the pipe -- */

#define PIPE_SIZE   65536
#define FD_SERVER   3
#define FD_CLIENT   4

typedef struct
{
    UBYTE   data[PIPE_SIZE];
    ULONG   head, tail;         /* tail - head bytes pending */
    ULONG   total;
} Pipe;

static Pipe     pipe_to_server, pipe_to_client;
static ULONG    stalls;

static Pipe *pipe_in(LONG fd)  { return (fd == FD_SERVER) ? &pipe_to_server : &pipe_to_client; }
static Pipe *pipe_out(LONG fd) { return (fd == FD_SERVER) ? &pipe_to_client : &pipe_to_server; }

/* Wait for input, yielding.  FALSE once nobody can produce any. */
static BOOL wait_input(LONG fd)
{
    Pipe *p = pipe_in(fd);
    ULONG spins = 0;

    while (p->tail == p->head)
    {
        if (fd == FD_CLIENT && co_srv_done)
            return FALSE;
        if (++spins > 4)
        {
            stalls++;
            return FALSE;       /* both sides waiting: a deadlock, report a timeout */
        }
        co_yield();
    }

    return TRUE;
}

static LONG fake_send(register LONG fd __asm("d0"), register const UBYTE *buf __asm("a0"),
                      register LONG len __asm("d1"), register LONG flags __asm("d2"))
{
    Pipe *p = pipe_out(fd);
    LONG  i;

    (void)flags;
    for (i = 0; i < len; i++)
        p->data[(p->tail++) % PIPE_SIZE] = buf[i];
    p->total += (ULONG)len;

    return len;
}

static LONG fake_recv(register LONG fd __asm("d0"), register UBYTE *buf __asm("a0"),
                      register LONG len __asm("d1"), register LONG flags __asm("d2"))
{
    Pipe *p = pipe_in(fd);
    LONG  n = 0;

    (void)flags;
    if (!wait_input(fd))
        return 0;

    while (n < len && p->head != p->tail)
        buf[n++] = p->data[(p->head++) % PIPE_SIZE];

    return n;
}

static LONG fake_getsockopt(register LONG fd __asm("d0"), register LONG level __asm("d1"),
                            register LONG name __asm("d2"), register LONG *val __asm("a0"),
                            register LONG *len __asm("a1"))
{
    (void)fd; (void)level; (void)name;
    *val = 1;                   /* SOCK_STREAM */
    *len = 4;
    return 0;
}

static LONG fake_getpeername(register LONG fd __asm("d0"), register UBYTE *sa __asm("a0"),
                             register LONG *len __asm("a1"))
{
    (void)fd;
    sa[0] = 16; sa[1] = 2; sa[2] = 0x1D; sa[3] = 0x13;
    sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;
    *len = 16;
    return 0;
}

static LONG fake_waitselect(register LONG nfds __asm("d0"), register ULONG *rd __asm("a0"),
                            register ULONG *wr __asm("a1"), register ULONG *ex __asm("a2"),
                            register APTR tv __asm("a3"), register ULONG *sig __asm("d1"))
{
    LONG fd = nfds - 1;

    (void)ex; (void)tv; (void)sig;
    if (wr != NULL)
        return 1;
    if (rd != NULL && !wait_input(fd))
    {
        rd[0] = 0;
        return 0;               /* timeout */
    }
    return 1;
}

static LONG fake_errno(void)
{
    return 35;                  /* EWOULDBLOCK */
}

/* The base and its jump table: six-byte JMP.L entries below the base. */
#define NEG_SIZE    168
static UWORD    fake_lib_mem[(NEG_SIZE + sizeof(struct Library) + 1) / 2 + 2];

static void set_vec(UBYTE *base, LONG lvo, APTR fn)
{
    UWORD *e = (UWORD *)(base + lvo);

    e[0] = 0x4EF9;
    e[1] = (UWORD)((ULONG)fn >> 16);
    e[2] = (UWORD)((ULONG)fn & 0xFFFFUL);
}

static struct Library *fake_socket_base(void)
{
    UBYTE          *base = (UBYTE *)fake_lib_mem + NEG_SIZE;
    struct Library *lib  = (struct Library *)base;
    LONG            lvo;

    for (lvo = -NEG_SIZE; lvo < 0; lvo += 6)
        set_vec(base, lvo, (APTR)fake_errno);
    set_vec(base, -66,  (APTR)fake_send);
    set_vec(base, -78,  (APTR)fake_recv);
    set_vec(base, -96,  (APTR)fake_getsockopt);
    set_vec(base, -108, (APTR)fake_getpeername);
    set_vec(base, -126, (APTR)fake_waitselect);
    set_vec(base, -162, (APTR)fake_errno);
    lib->lib_NegSize = NEG_SIZE;
    lib->lib_PosSize = sizeof(struct Library);
    CacheClearU();

    return lib;
}

/* --------------------------------------------------------------- the run -- */

static struct Library  *sock_base;
static STRPTR           a_cert, a_key, a_store, a_host;
static ULONG            a_keytype;
static struct TLSConnection *srv_tls, *cli_tls;
static LONG             srv_err, cli_err;

static void co_server(void)
{
    srv_tls = TLSOpen(TLSBase, (APTR)sock_base, FD_SERVER,
                      TLSA_Server,      (ULONG)TRUE,
                      TLSA_Certificate, (ULONG)a_cert,
                      TLSA_PrivateKey,  (ULONG)a_key,
                      TLSA_KeyType,     a_keytype,
                      TLSA_Timeout,     240000UL,
                      TLSA_Error,       (ULONG)&srv_err,
                      TAG_DONE);
    co_srv_done = 1;
    for (;;)
    {
        co_in_server = 0;
        co_switch(&co_srv_sp, co_main_sp);
    }
}

#define TEMPLATE "CERT/K/A,KEY/K/A,KEYTYPE/K,STORE/K/A,HOST/K/A"

int main(void)
{
    LONG             args[5] = { 0, 0, 0, 0, 0 };
    struct RDArgs   *rd;
    ULONG           *stack;
    int              rc = 20;

    rd = ReadArgs((STRPTR)TEMPLATE, args, NULL);
    if (rd == NULL)
    {
        PutStr((STRPTR)"coloop_args=fail\n");
        return 20;
    }
    a_cert  = (STRPTR)args[0];
    a_key   = (STRPTR)args[1];
    a_keytype = (args[2] != 0 && ((STRPTR)args[2])[0] == 'E') ? TLS_KEY_EC : TLS_KEY_RSA;
    a_store = (STRPTR)args[3];
    a_host  = (STRPTR)args[4];

    TLSBase = OpenLibrary((STRPTR)TLS_LIB_NAME, 1);
    if (TLSBase == NULL)
    {
        PutStr((STRPTR)"coloop_open_tls=fail\n");
        FreeArgs(rd);
        return 20;
    }

    sock_base = fake_socket_base();

    stack = (ULONG *)AllocMem(CO_STACK, MEMF_ANY | MEMF_CLEAR);
    if (stack == NULL)
    {
        PutStr((STRPTR)"coloop_stack=fail\n");
        CloseLibrary(TLSBase);
        FreeArgs(rd);
        return 20;
    }
    /* initial frame: 11 saved registers, then the return address */
    co_srv_sp = (ULONG)stack + CO_STACK - 16 - 48;
    ((ULONG *)co_srv_sp)[11] = (ULONG)co_server;

    PutStr((STRPTR)"coloop_start=ok\n");
    Flush(Output());

    /* The server runs first, up to its first read, then the client starts. */
    co_in_server = 1;
    co_switch(&co_main_sp, co_srv_sp);

    cli_tls = TLSOpen(TLSBase, (APTR)sock_base, FD_CLIENT,
                      TLSA_HostName,   (ULONG)a_host,
                      TLSA_TrustStore, (ULONG)a_store,
                      TLSA_NoResume,   (ULONG)TRUE,
                      TLSA_Timeout,    240000UL,
                      TLSA_Error,      (ULONG)&cli_err,
                      TAG_DONE);

    /* Let the server finish its side. */
    while (!co_srv_done)
    {
        co_in_server = 1;
        co_switch(&co_main_sp, co_srv_sp);
        if (pipe_to_server.head == pipe_to_server.tail && !co_srv_done)
            break;
    }

    Printf((STRPTR)"coloop_client=%s\ncoloop_client_error=%ld\n", (ULONG)(cli_tls ? "ok" : "fail"), cli_err);
    Printf((STRPTR)"coloop_server=%s\ncoloop_server_error=%ld\n", (ULONG)(srv_tls ? "ok" : (co_srv_done ? "fail" : "blocked")), srv_err);
    Printf((STRPTR)"coloop_bytes_c2s=%lu\ncoloop_bytes_s2c=%lu\ncoloop_yields=%lu\ncoloop_stalls=%lu\n",
           pipe_to_server.total, pipe_to_client.total, co_yields, stalls);

    if (cli_tls != NULL && srv_tls != NULL)
    {
        static const char ping[] = "AmiNetXDuo TlsCoLoop request\n";
        static const char pong[] = "AmiNetXDuo TlsCoLoop response\n";
        struct TLSInfo    info;
        UBYTE             buf[64];
        BOOL              ok;
        ULONG             i;

        for (i = 0; i < sizeof(info); i++)
            ((UBYTE *)&info)[i] = 0;
        info.ti_Size = sizeof(info);
        if (TLSInfo(TLSBase, cli_tls, &info) == TLS_OK)
            Printf((STRPTR)"coloop_version=0x%lx\ncoloop_suite=0x%lx\n",
                   info.ti_Version, info.ti_CipherSuite);

        /* One application record each way: the record path in both
           directions, after the handshake's own Finished pair. */
        ok = (TLSWrite(TLSBase, cli_tls, (CONST_APTR)ping, sizeof(ping) - 1) ==
              (LONG)(sizeof(ping) - 1)) &&
             (TLSRead(TLSBase, srv_tls, (APTR)buf, sizeof(buf)) ==
              (LONG)(sizeof(ping) - 1));
        for (i = 0; ok && i < sizeof(ping) - 1; i++)
            ok = (BOOL)(buf[i] == (UBYTE)ping[i]);
        ok = ok &&
             (TLSWrite(TLSBase, srv_tls, (CONST_APTR)pong, sizeof(pong) - 1) ==
              (LONG)(sizeof(pong) - 1)) &&
             (TLSRead(TLSBase, cli_tls, (APTR)buf, sizeof(buf)) ==
              (LONG)(sizeof(pong) - 1));
        for (i = 0; ok && i < sizeof(pong) - 1; i++)
            ok = (BOOL)(buf[i] == (UBYTE)pong[i]);
        Printf((STRPTR)"coloop_records=%s\n", (ULONG)(ok ? "ok" : "fail"));

        if (ok)
            rc = 0;
    }

    if (cli_tls != NULL)
        TLSClose(TLSBase, cli_tls);
    if (srv_tls != NULL)
        TLSClose(TLSBase, srv_tls);
    /* A server that never finished is still standing on its stack. */
    if (co_srv_done)
        FreeMem(stack, CO_STACK);
    CloseLibrary(TLSBase);

    Printf((STRPTR)"RESULT=%s\n", (ULONG)(rc == 0 ? "PASS" : "FAIL"));
    FreeArgs(rd);
    return rc;
}
