/* Bounded receive sweep policy, independent of AmigaOS. SPDX-License-Identifier: MIT */
#ifndef RXSWEEP_H
#define RXSWEEP_H
#include <stdint.h>
#define RXSWEEP_KNOBS 7
#define RXSWEEP_LIST 8
#define RXSWEEP_CASES 64
#define RXSWEEP_REPEATS 9

typedef struct { uint32_t v[RXSWEEP_KNOBS]; } RxSweepValues;
typedef struct { uint32_t v[RXSWEEP_LIST]; unsigned n; } RxSweepList;
typedef struct {
    RxSweepValues saved, cases[RXSWEEP_CASES];
    unsigned count, repeats;
} RxSweepPlan;
typedef struct { uint32_t bits; int valid; } RxSweepSample;
typedef struct {
    uint32_t rates[RXSWEEP_REPEATS];
    unsigned count, invalid;
} RxSweepScores;
typedef struct {
    RxSweepScores before, after, cases[RXSWEEP_CASES];
} RxSweepResults;
typedef struct {
    /* restoring must ignore cancellation; apply can fail after mutation. */
    int (*apply)(void *, const RxSweepValues *, int restoring);
    int (*measure)(void *, RxSweepSample *);
    int (*record)(void *, int phase, unsigned candidate, unsigned repeat,
                  const RxSweepValues *, const RxSweepSample *);
    int (*stopped)(void *);
} RxSweepOps;
/* phase: 0 baseline before, 1 candidate, 2 baseline after. */
int rxsweep_list(const char *, uint32_t max, RxSweepList *);
int rxsweep_plan(RxSweepPlan *, const RxSweepList lists[RXSWEEP_KNOBS]);
uint32_t rxsweep_median(const RxSweepScores *);
/* 0 complete, -1 stopped/failed, -2 restoration failed. Always restores. */
int rxsweep_run(const RxSweepPlan *, RxSweepResults *, const RxSweepOps *, void *);

typedef struct {
    int (*online)(void *, int online); /* 0 success, -1 failure */
    int (*busy)(void *);              /* 0 idle, 1 active TCP, -1 query failure */
    int (*write)(void *, const RxSweepValues *); /* 0 success, 1 busy, -1 failure */
    int (*stopped)(void *);
    uint32_t (*millis)(void *);
    void (*pause)(void *);            /* yield briefly, always while online */
} RxSweepChangeOps;
/* Drain while ONLINE, offline/write/online, retry EBUSY while ONLINE.
   Bounded even during recovery, which ignores cancellation. */
int rxsweep_change(const RxSweepChangeOps *, void *, const RxSweepValues *,
                   int restoring, uint32_t timeout_ms);
#endif
