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
int main(void)
{
    RxSweepList lists[RXSWEEP_KNOBS], list;
    RxSweepScores median = {{40, 10, 20}, 3, 0};
    unsigned k, i, total;
    Fake f = {0};
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
    puts("receive sweep: parser, grid, ordering, ranking and restoration passed");
    return 0;
}
