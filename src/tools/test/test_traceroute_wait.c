/*
 * F-204: traceroute's WAIT deadline.  Two things were wrong and are fixed
 * together here.
 *
 * 1. The deadline `t0 + wait * 10000UL` is compared with a signed 32-bit
 *    difference, so the span `wait * 10000` tenths of a millisecond must stay
 *    under 2^31.  WAIT is now capped at TR_CEILING_WAIT = 0x7FFFFFFF/10000 =
 *    214748 seconds, the largest whole-second wait whose span stays under the
 *    signed half-range.
 *
 * 2. tr_now() read only the EClock low word, so its tenths-of-a-millisecond
 *    output wrapped to 0 every ~100 minutes (2^32 ticks / ~710 kHz).  A probe
 *    whose wait straddled that wrap -- even a short one -- never reached its
 *    deadline.  tr_now() now divides a full 64-bit EClock delta
 *    (ev_hi:ev_lo minus epoch_hi:epoch_lo, with the low-word borrow) by the
 *    full measured rate, so a tenth of a millisecond is exact and the 32-bit
 *    output wraps only every ~4.97 days.
 *
 * The clock is exercised VERBATIM: extract_tr_clock.py pulls tr_now() and
 * tr_clock_open() out of traceroute.c at build time, and this file compiles
 * those real functions against a stubbed ReadEClock, so the test never re-types
 * the arithmetic it is proving.  The cap's source and numeric boundary are
 * locked separately.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef AMINETXDUO_SOURCE_DIR
#define AMINETXDUO_SOURCE_DIR "."
#endif

/* The AmigaOS types the extracted block uses, in host form. */
typedef uint32_t ULONG;
typedef int32_t  LONG;
typedef int      BOOL;

#define TRUE  1
#define FALSE 0
#define VOID  void

struct Device    { int dummy; };
struct EClockVal { ULONG ev_hi; ULONG ev_lo; };

/* timer.device / compat.c, stubbed: the extracted block only reads through
   TimerBase and divides by the rate, so the stubs script both. */
struct Device *TimerBase;

static struct Device    fake_timer;
static struct EClockVal fake_ev;
static ULONG            fake_rate;

ULONG ReadEClock(struct EClockVal *dest)
{
    *dest = fake_ev;
    return fake_rate;
}

ULONG ami_millis(void)
{
    return 0;
}

/* The production clock, verbatim from traceroute.c. */
#include "tr_clock.inc"

static int failures;
static int checks;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                    \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

/* Open the clock with a scripted epoch and rate: tr_clock_open() captures
   fake_ev into tr_epoch and fake_rate into tr_rate. */
static void open_clock(ULONG hi, ULONG lo, ULONG rate)
{
    TimerBase = &fake_timer;
    fake_ev.ev_hi = hi;
    fake_ev.ev_lo = lo;
    fake_rate = rate;
    if (!tr_clock_open()) {
        printf("  FAIL %s:%d: tr_clock_open() refused a set TimerBase\n",
               __FILE__, __LINE__);
        exit(1);
    }
}

/* Set the current clock to (hi, lo) and read tr_now(). */
static ULONG now_at(ULONG hi, ULONG lo)
{
    fake_ev.ev_hi = hi;
    fake_ev.ev_lo = lo;
    return tr_now();
}

/* Set the current clock to `ticks` past the epoch and read tr_now(). */
static ULONG now_after_ticks(uint64_t ticks)
{
    fake_ev.ev_hi = (ULONG)(ticks >> 32);
    fake_ev.ev_lo = (ULONG)(ticks & 0xFFFFFFFFu);
    return tr_now();
}

static char *slurp(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long  n;
    char *buf;

    if (fp == NULL)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    n = ftell(fp);
    if (n < 0) { fclose(fp); return NULL; }
    rewind(fp);
    buf = malloc((size_t)n + 1);
    if (buf == NULL) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) { free(buf); fclose(fp); return NULL; }
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Comments and string literals out, so a sentence that NAMES a token is not
   read as the token. */
static void code_only(char *s)
{
    char *r = s;
    char *w = s;

    while (*r != '\0') {
        if (r[0] == '/' && r[1] == '*') {
            r += 2;
            while (*r != '\0' && !(r[0] == '*' && r[1] == '/'))
                r++;
            if (*r != '\0')
                r += 2;
            *w++ = ' ';
            continue;
        }
        if (r[0] == '/' && r[1] == '/') {
            while (*r != '\0' && *r != '\n')
                r++;
            continue;
        }
        if (*r == '"' || *r == '\'') {
            char q = *r++;

            while (*r != '\0' && *r != q) {
                if (*r == '\\' && r[1] != '\0')
                    r++;
                r++;
            }
            if (*r != '\0')
                r++;
            *w++ = q;
            *w++ = q;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static int ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* How many times `name` appears as a whole identifier. */
static int uses(const char *code, const char *name)
{
    const char *p = code;
    size_t      n = strlen(name);
    int         count = 0;

    while ((p = strstr(p, name)) != NULL) {
        if ((p == code || !ident_char(p[-1])) && !ident_char(p[n]))
            count++;
        p += n;
    }
    return count;
}

/* wait seconds -> tenths of a ms, 32-bit like m68k. */
static uint32_t span_tenths(uint32_t wait_s)
{
    return (uint32_t)(wait_s * 10000UL);
}

int main(void)
{
    char *code;
    char  path[1024];
    const uint32_t half    = 0x80000000UL;
    const uint32_t ceiling = (0x7FFFFFFFUL) / 10000UL;

    /* ---- the production clock, run verbatim (part 2 of the fix) ---- */

    /* A nonzero epoch whose low word is high: crossing the low-word wrap
       borrows from the high word.  512 ticks at 700000/s = 7 tenths-ms; if the
       borrow were dropped, hi would stay 1 and tr_now() would read ~61.36M. */
    open_clock(5, 0xFFFFFF00u, 700000);
    CHECK(now_at(6, 0x00000100u) == 7u,
          "borrow across the low-word wrap: 512 ticks == 7 tenths-ms, not ~61M");

    /* The full-rate division: 1 real second is exactly 10000 tenths-ms.  The
       old `rate/10000` divisor (70 at this rate) read 709379/70 = 10134, ~1.3%
       fast. */
    open_clock(0, 0, 709379);
    CHECK(now_after_ticks(709379ULL) == 10000u,
          "1 s at 709379 ticks/s == exactly 10000 tenths-ms");

    /* The largest accepted span: WAIT = 214748 s of ticks maps to exactly
       2147480000 tenths-ms, still under 2^31. */
    open_clock(0, 0, 709379);
    CHECK(now_after_ticks(214748ULL * 709379ULL) == 2147480000u,
          "214748 s == 2147480000 tenths-ms (the maximum accepted span)");

    /* A deadline that straddles the 32-bit output wrap.  rate = 700000, so
       tr_now() = ticks / 70 exactly. */
    open_clock(0, 0, 700000);
    {
        const uint32_t t0 = now_after_ticks(70ULL * 0xFFFFFFF0ULL);

        CHECK(t0 == 0xFFFFFFF0u,
              "t0 == 4294967280 tenths-ms (16 before the wrap)");

        /* The 5 s wait wraps the deadline mod 2^32, as it does on m68k. */
        const uint32_t deadline = (uint32_t)(t0 + 5UL * 10000UL);
        CHECK(deadline == 49984u, "the 5 s deadline wraps to 49984");

        const uint32_t before = now_after_ticks(70ULL * 49983ULL);
        const uint32_t at     = now_after_ticks(70ULL * 49984ULL);

        CHECK(before == 49983u, "now just before expiry == 49983");
        CHECK(!((LONG)(before - deadline) >= 0), "just before: not yet expired");
        CHECK(at == 49984u, "now at expiry == 49984");
        CHECK(((LONG)(at - deadline) >= 0), "at expiry: expired");
    }

    /* ---- the WAIT cap (part 1 of the fix) ---- */

    snprintf(path, sizeof(path), "%s/src/tools/traceroute.c",
             getenv("AMINETXDUO_SOURCE_DIR") != NULL ?
             getenv("AMINETXDUO_SOURCE_DIR") : AMINETXDUO_SOURCE_DIR);
    code = slurp(path);
    CHECK(code != NULL, "cannot read %s", path);
    if (code != NULL) {
        /* The refusal names the ceiling; checked on the raw source because
           code_only() strips the string literal. */
        CHECK(strstr(code, "WAIT is at most") != NULL,
              "the refusal names the ceiling");

        code_only(code);

        CHECK(uses(code, "TR_CEILING_WAIT") == 3,
              "ceiling is defined, checked, and named in the refusal");
        CHECK(uses(code, "0x7FFFFFFFUL") == 1,
              "ceiling is the signed half-range over tenths-of-ms-per-second");
        CHECK(strstr(code, "wait > TR_CEILING_WAIT") != NULL,
              "an over-long WAIT is refused before the deadline is built");

        free(code);
    }

    CHECK(ceiling == 214748UL, "TR_CEILING_WAIT == 214748 s");
    CHECK(span_tenths(5UL) == 50000UL, "5 s -> 50000 tenths of a ms");
    CHECK(span_tenths(ceiling) < half,
          "214748 s stays under 2^31 (the last safe WAIT)");
    CHECK(span_tenths(ceiling + 1UL) >= half,
          "214749 s crosses 2^31 (the first unsafe WAIT)");

    if (failures != 0) {
        printf("%d checks, %d failure(s)\n", checks, failures);
        return 1;
    }
    printf("%d checks, 0 failures\n", checks);
    return 0;
}
