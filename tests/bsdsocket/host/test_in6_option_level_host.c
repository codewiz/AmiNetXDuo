/* ICMPv6 optnames must not alias IPv6 socket options when CMSG is disabled. */
#include "bsdsocket_vectors.h"

#include <stdio.h>
#include <string.h>

static struct AmiSocketBase h_base;
static AmiSocket h_sock;
static int h_checks;
static int h_failures;

#define CHECK(expr) do { h_checks++; if (!(expr)) { \
    h_failures++; printf("FAIL line %d: %s\n", __LINE__, #expr); \
} } while (0)

LONG bsd_fail(struct AmiSocketBase *base, LONG code)
{
    base->sb_Errno = code;
    return -1;
}

VOID bsd_bcopy(CONST_APTR src, APTR dst, ULONG size)
{
    memcpy(dst, src, size);
}

LONG bsd_cmsg_option(struct AmiSocketBase *base, AmiSocket *sock, LONG level,
                     LONG optname, APTR optval, socklen_t *optlen, BOOL set)
{
    (VOID)base; (VOID)sock; (VOID)level; (VOID)optname;
    (VOID)optval; (VOID)optlen; (VOID)set;
    return 1; /* CMSG=OFF contract: not handled here. */
}

LONG bsd_nx_enter(struct AmiSocketBase *base) { (VOID)base; return 0; }
VOID bsd_nx_leave(struct AmiSocketBase *base) { (VOID)base; }
VOID bsd_opt_apply_ip(AmiSocket *sock) { (VOID)sock; }

/* This host shim has Linux socket layouts; the target ABI assertions are
   covered by the m68k build, while this test exercises the option logic. */
#define _Static_assert(condition, message)
#include "in6.c"
#undef _Static_assert

int main(void)
{
    LONG value = 42;
    socklen_t len = (socklen_t)sizeof(value);

    memset(&h_base, 0, sizeof(h_base));
    memset(&h_sock, 0, sizeof(h_sock));
    h_sock.as_Flags = ASF_INET6;
    h_sock.as_Ttl = 9;

    CHECK(bsd_setsockopt_ipv6(&h_base, &h_sock, IPPROTO_ICMPV6,
                              AMI_IPV6_UNICAST_HOPS_BSD, &value,
                              (socklen_t)sizeof(value)) == -1);
    CHECK(h_base.sb_Errno == AMI_ENOPROTOOPT);
    CHECK(h_sock.as_Ttl == 9);

    CHECK(bsd_getsockopt_ipv6(&h_base, &h_sock, IPPROTO_ICMPV6,
                              AMI_IPV6_UNICAST_HOPS_BSD, &value, &len) == -1);
    CHECK(h_base.sb_Errno == AMI_ENOPROTOOPT);
    CHECK(value == 42);

    CHECK(bsd_setsockopt_ipv6(&h_base, &h_sock, IPPROTO_IPV6,
                              AMI_IPV6_UNICAST_HOPS_BSD, &value,
                              (socklen_t)sizeof(value)) == 0);
    CHECK(h_sock.as_Ttl == 42);
    value = 0;
    CHECK(bsd_getsockopt_ipv6(&h_base, &h_sock, IPPROTO_IPV6,
                              AMI_IPV6_UNICAST_HOPS_BSD, &value, &len) == 0);
    CHECK(value == 42);

    printf("RESULT in6_option_level checks=%d failures=%d\n",
           h_checks, h_failures);
    return h_failures != 0;
}
