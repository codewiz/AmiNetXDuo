/*
 * nslookup's TXT join (F-171): up to 255 bytes come out exactly, anything
 * beyond is counted as omitted rather than dropped silently, and a string
 * that runs past the record is still refused.
 *
 * SPDX-License-Identifier: MIT
 */
#include "nsltxt.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static unsigned char msg[1024];
static char          out[256];

/* Strings of the given lengths, filled 'a', 'b', ... */
static unsigned long build(const unsigned long *lens, int count)
{
    unsigned long p = 0;
    int k;

    for (k = 0; k < count; k++)
    {
        msg[p++] = (unsigned char)lens[k];
        memset(&msg[p], 'a' + k, lens[k]);
        p += lens[k];
    }
    return p;
}

int main(void)
{
    unsigned long omitted;
    unsigned long end;

    {   /* One 255-byte string fits exactly. */
        const unsigned long l[] = { 255 };
        end = build(l, 1);
        CHECK(nsl_txt_join(msg, 0, end, out, sizeof(out), &omitted) == 1);
        CHECK(strlen(out) == 255 && omitted == 0);
    }
    {   /* Two strings joining past the buffer: the rest is counted. */
        const unsigned long l[] = { 200, 100 };
        end = build(l, 2);
        CHECK(nsl_txt_join(msg, 0, end, out, sizeof(out), &omitted) == 1);
        CHECK(strlen(out) == 255 && omitted == 45);
        CHECK(out[199] == 'a' && out[200] == 'b');
    }
    {   /* Short and unchanged. */
        const unsigned long l[] = { 3, 2 };
        end = build(l, 2);
        CHECK(nsl_txt_join(msg, 0, end, out, sizeof(out), &omitted) == 1);
        CHECK(strcmp(out, "aaabb") == 0 && omitted == 0);
    }
    {   /* A string longer than the record is still malformed. */
        msg[0] = 10; memset(&msg[1], 'x', 5);
        CHECK(nsl_txt_join(msg, 0, 6, out, sizeof(out), &omitted) == 0);
    }
    {   /* Control bytes are shown as '?'. */
        msg[0] = 2; msg[1] = 0x07; msg[2] = 'z';
        CHECK(nsl_txt_join(msg, 0, 3, out, sizeof(out), &omitted) == 1);
        CHECK(strcmp(out, "?z") == 0);
    }

    printf("nsltxt: %d checks, %d failure(s)\n", checks, failures);
    return failures != 0;
}
