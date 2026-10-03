/* SPDX-License-Identifier: MIT */
#include "rxsweep.h"
#include <string.h>

int rxsweep_list(const char *s, uint32_t max, RxSweepList *out)
{
    RxSweepList list = {{0}, 0};
    if (!s || !*s) return 0;
    for (;;) {
        uint32_t n = 0;
        unsigned i;
        if (*s < '0' || *s > '9') return 0;
        do {
            unsigned digit = (unsigned)(*s++ - '0');
            if (digit > max || n > (max - digit) / 10) return 0;
            n = n * 10 + digit;
        } while (*s >= '0' && *s <= '9');
        for (i = 0; i < list.n && list.v[i] != n; ++i) {}
        if (i == list.n) {
            if (list.n == RXSWEEP_LIST) return 0;
            list.v[list.n++] = n;
        }
        if (!*s) { *out = list; return 1; }
        if (*s++ != ',') return 0;
    }
}

int rxsweep_plan(RxSweepPlan *p, const RxSweepList lists[RXSWEEP_KNOBS])
{
    unsigned k, n, total = 1;
    if (!p->repeats || p->repeats > RXSWEEP_REPEATS || !(p->repeats & 1)) return 0;
    for (k = 0; k < RXSWEEP_KNOBS; ++k) {
        if (!lists[k].n || lists[k].n > RXSWEEP_LIST ||
            total > RXSWEEP_CASES / lists[k].n) return 0;
        total *= lists[k].n;
    }
    p->count = 0;
    for (n = 0; n < total; ++n) {
        RxSweepValues v;
        unsigned idx = n;
        for (k = 0; k < RXSWEEP_KNOBS; ++k) {
            v.v[k] = lists[k].v[idx % lists[k].n];
            idx /= lists[k].n;
        }
        /* The exact original settings already get two baseline groups. */
        if (memcmp(&v, &p->saved, sizeof(v))) p->cases[p->count++] = v;
    }
    return 1;
}

uint32_t rxsweep_median(const RxSweepScores *s)
{
    uint32_t sorted[RXSWEEP_REPEATS];
    unsigned i, j;
    if (!s->count || s->invalid) return 0;
    for (i = 0; i < s->count; ++i) {
        uint32_t v = s->rates[i];
        for (j = i; j && sorted[j - 1] > v; --j) sorted[j] = sorted[j - 1];
        sorted[j] = v;
    }
    return sorted[s->count / 2];
}

static int trial(const RxSweepOps *ops, void *ctx, const RxSweepValues *v,
                 RxSweepScores *scores, int phase, unsigned n, unsigned r)
{
    RxSweepSample sample = {0, 0};
    if (ops->stopped(ctx) || ops->apply(ctx, v, 0) || ops->stopped(ctx) ||
        ops->measure(ctx, &sample)) return -1;
    scores->rates[scores->count++] = sample.bits;
    if (!sample.valid) ++scores->invalid;
    return ops->record(ctx, phase, n, r, v, &sample);
}

int rxsweep_run(const RxSweepPlan *p, RxSweepResults *out,
                const RxSweepOps *ops, void *ctx)
{
    unsigned r, n;
    int rc = -1;
    memset(out, 0, sizeof(*out));
    for (r = 0; r < p->repeats; ++r)
        if (trial(ops, ctx, &p->saved, &out->before, 0, 0, r)) goto restore;
    /* Rotate the order per repetition, spreading gradual drift across cases. */
    for (r = 0; r < p->repeats; ++r)
        for (n = 0; n < p->count; ++n) {
            unsigned i = (n + r) % p->count;
            if (trial(ops, ctx, &p->cases[i], &out->cases[i], 1, i, r)) goto restore;
        }
    for (r = 0; r < p->repeats; ++r)
        if (trial(ops, ctx, &p->saved, &out->after, 2, 0, r)) goto restore;
    rc = 0;
restore:
    if (ops->apply(ctx, &p->saved, 1)) return -2;
    return rc;
}
