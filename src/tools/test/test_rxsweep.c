/* Exercise restoration through failures at every transaction boundary.
 * SPDX-License-Identifier: MIT */
#include "rxsweep.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>

static RxSweepPlan plan;
static RxSweepResults results;
typedef struct {
    RxSweepValues current;
    unsigned applies, measures, records, restores;
    unsigned fail_apply, fail_measure, fail_record, cancel_after;
    int fail_restore, invalid;
} Fake;
static int apply(void *ctx, const RxSweepValues *v, int restoring)
{
    Fake *f = ctx;
    f->current = *v; /* failures may have already changed the machine */
    if (restoring) { ++f->restores; return f->fail_restore; }
    return ++f->applies == f->fail_apply ? -1 : 0;
}
static int measure(void *ctx, RxSweepSample *sample)
{
    Fake *f = ctx;
    sample->bits = 100 + f->current.v[0]; sample->valid = !f->invalid;
    return ++f->measures == f->fail_measure ? -1 : 0;
}
static int record(void *ctx, int phase, unsigned c, unsigned repeat,
                  const RxSweepValues *v, const RxSweepSample *s)
{
    Fake *f = ctx;
    assert(phase >= 0 && phase <= 2 && repeat < plan.repeats);
    assert(c < plan.count || phase != 1);
    assert(s->bits == 100 + v->v[0]);
    if (phase == 1) {
        unsigned pos = f->records - plan.repeats;
        assert(repeat == pos / plan.count);
        assert(c == (pos % plan.count + repeat) % plan.count);
    }
    return ++f->records == f->fail_record ? -1 : 0;
}
static int stopped(void *ctx)
{
    Fake *f = ctx;
    return f->cancel_after && f->records >= f->cancel_after;
}
static const RxSweepOps ops = {apply, measure, record, stopped};
static void restored(Fake *f)
{
    assert(f->restores == 1);
    assert(!memcmp(&f->current, &plan.saved, sizeof(plan.saved)));
}

/* Model a FIN that can progress ONLY while online, plus an incoming
   connection racing the preflight. The old offline retry loop deadlocked
   both cases. Run the same transaction code as the Amiga command. */
typedef struct {
    uint32_t now, drain_at;
    unsigned writes, offlines, pauses, busy_writes;
    int online, cancel, fail_query, fail_write, fail_offline, fail_online;
    RxSweepValues current;
} Link;
static int link_online(void *ctx, int online)
{
    Link *l = ctx;
    l->online = online;
    if (!online) ++l->offlines;
    return online ? l->fail_online : l->fail_offline;
}
static int link_busy(void *ctx)
{
    Link *l = ctx;
    assert(l->online);
    return l->fail_query ? -1 : l->drain_at != 0;
}
static int link_write(void *ctx, const RxSweepValues *values)
{
    Link *l = ctx;
    assert(!l->online);
    ++l->writes;
    if (l->writes <= l->busy_writes) {
        l->drain_at = 1000;
        return 1;
    }
    if (l->fail_write) return -1;
    l->current = *values;
    return 0;
}
static int link_stopped(void *ctx) { return ((Link *)ctx)->cancel; }
static uint32_t link_millis(void *ctx) { return ((Link *)ctx)->now; }
static void link_pause(void *ctx)
{
    Link *l = ctx;
    assert(l->online); /* no pause, even on a busy retry, may be offline */
    ++l->pauses;
    l->now += 100;
    if (l->drain_at) l->drain_at -= 100;
}
static void test_drain(void)
{
    static const RxSweepChangeOps change = {
        link_online, link_busy, link_write, link_stopped, link_millis, link_pause
    };
    RxSweepValues v = {{128, 4, 65536, 2, 1, 64, 4}};
    Link l = {0};
    l.drain_at = 7000; /* longer than the old five-second retry budget */
    assert(!rxsweep_change(&change, &l, &v, 0, 30000));
    assert(l.online && l.writes == 1 && l.offlines == 1 && l.pauses == 70);
    assert(!memcmp(&l.current, &v, sizeof(v)));
    memset(&l, 0, sizeof(l)); l.busy_writes = 2;
    assert(!rxsweep_change(&change, &l, &v, 0, 30000));
    assert(l.online && l.writes == 3 && l.pauses == 20);
    memset(&l, 0, sizeof(l)); l.drain_at = 40000;
    assert(rxsweep_change(&change, &l, &v, 0, 30000) == -1);
    assert(l.online && !l.writes && !l.offlines);
    /* Recovery starts a fresh budget and ignores the latched Ctrl-C. */
    l.cancel = 1;
    assert(!rxsweep_change(&change, &l, &v, 1, 60000));
    assert(l.online && l.writes == 1);
    memset(&l, 0, sizeof(l)); l.drain_at = 70000; l.cancel = 1;
    assert(rxsweep_change(&change, &l, &v, 1, 60000) == -1);
    assert(l.online && !l.offlines && l.pauses == 600);
    memset(&l, 0, sizeof(l)); l.cancel = 1;
    assert(rxsweep_change(&change, &l, &v, 0, 30000) == -1);
    assert(l.online && !l.offlines);
    memset(&l, 0, sizeof(l)); l.fail_query = 1;
    assert(rxsweep_change(&change, &l, &v, 0, 30000) == -1);
    assert(l.online && !l.offlines);
    memset(&l, 0, sizeof(l)); l.fail_write = 1;
    assert(rxsweep_change(&change, &l, &v, 0, 30000) == -1);
    assert(l.online && l.writes == 1);
    memset(&l, 0, sizeof(l)); l.fail_offline = 1;
    assert(rxsweep_change(&change, &l, &v, 1, 60000) == -1);
    assert(l.online && !l.writes);
    memset(&l, 0, sizeof(l)); l.fail_online = 1;
    assert(rxsweep_change(&change, &l, &v, 1, 60000) == -1);
    assert(!l.writes);
    memset(&l, 0, sizeof(l)); l.now = UINT32_MAX - 500; l.drain_at = 2000;
    assert(rxsweep_change(&change, &l, &v, 0, 1000) == -1);
    assert(l.online && l.pauses == 10); /* timer wrap stays bounded */
}
int main(void)
{
    RxSweepList lists[RXSWEEP_KNOBS], list;
    RxSweepScores median = {{40, 10, 20}, 3, 0};
    unsigned k, i, total;
    Fake f = {0};
    test_drain();
    assert(rxsweep_list("0,8,16,8", 128, &list) && list.n == 3);
    assert(!rxsweep_list("129", 128, &list));
    assert(!rxsweep_list("4294967296", UINT32_MAX, &list));
    assert(rxsweep_list("4294967295", UINT32_MAX, &list));
    assert(!rxsweep_list("-1", 128, &list));
    assert(!rxsweep_list("1,", 128, &list));
    assert(!rxsweep_list("1,,2", 128, &list));
    assert(!rxsweep_list("", 128, &list));
    assert(!rxsweep_list("1x", 128, &list));
    assert(!rxsweep_list("1,2,3,4,5,6,7,8,9", 128, &list));
    assert(rxsweep_median(&median) == 20);
    median.invalid = 1; assert(!rxsweep_median(&median));
    for (k = 0; k < RXSWEEP_KNOBS; ++k) {
        plan.saved.v[k] = (k == 0 || k == 2) ? 0 : 7 + k;
        lists[k].n = 1; lists[k].v[0] = plan.saved.v[k];
    }
    assert(rxsweep_list("0,8,16", 128, &lists[0]));
    assert(rxsweep_list("0,16384,65536", 16777216, &lists[2]));
    plan.repeats = 3;
    assert(rxsweep_plan(&plan, lists) && plan.count == 8);
    total = (plan.count + 2) * plan.repeats;
    assert(!rxsweep_run(&plan, &results, &ops, &f)); restored(&f);
    assert(f.records == total && f.measures == total && f.applies == total);
    assert(results.before.count == 3 && results.after.count == 3);
    for (i = 0; i < plan.count; ++i) {
        assert(results.cases[i].count == 3);
        for (k = 0; k < RXSWEEP_KNOBS; ++k)
            if (k != 0 && k != 2) assert(plan.cases[i].v[k] == plan.saved.v[k]);
    }
    for (i = 1; i <= total; ++i) {
        memset(&f, 0, sizeof(f)); f.fail_apply = i;
        assert(rxsweep_run(&plan, &results, &ops, &f) == -1); restored(&f);
        memset(&f, 0, sizeof(f)); f.fail_measure = i;
        assert(rxsweep_run(&plan, &results, &ops, &f) == -1); restored(&f);
        memset(&f, 0, sizeof(f)); f.fail_record = i;
        assert(rxsweep_run(&plan, &results, &ops, &f) == -1); restored(&f);
        if (i < total) {
            memset(&f, 0, sizeof(f)); f.cancel_after = i;
            assert(rxsweep_run(&plan, &results, &ops, &f) == -1); restored(&f);
        }
    }
    memset(&f, 0, sizeof(f)); f.fail_restore = 1;
    assert(rxsweep_run(&plan, &results, &ops, &f) == -2);
    memset(&f, 0, sizeof(f)); f.invalid = 1;
    assert(!rxsweep_run(&plan, &results, &ops, &f)); restored(&f);
    for (i = 0; i < plan.count; ++i) assert(!rxsweep_median(&results.cases[i]));
    memset(&plan.saved, 0, sizeof(plan.saved));
    for (k = 0; k < RXSWEEP_KNOBS; ++k)
        assert(rxsweep_list("0,1", 128, &lists[k]));
    assert(!rxsweep_plan(&plan, lists)); /* 128 > cap */
    lists[6].n = 1; assert(rxsweep_plan(&plan, lists) && plan.count == 63);
    plan.repeats = 2; assert(!rxsweep_plan(&plan, lists));
    plan.repeats = 10; assert(!rxsweep_plan(&plan, lists));
    puts("receive sweep: online drain/retry, parser, grid, ordering, ranking and restoration passed");
    return 0;
}
