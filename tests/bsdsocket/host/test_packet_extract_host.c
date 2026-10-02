/*
 * Regression coverage for bsdsocket's TCP receive extractors.
 * The helper is included directly so this test executes the same inline code
 * transfer.c ships; the fallback is NetX Duo's vendored implementation.
 *
 * SPDX-License-Identifier: MIT
 */

#include "packet_extract.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                        \
    do {                                                                   \
        if (!(expr)) {                                                     \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr);       \
            return 1;                                                      \
        }                                                                  \
    } while (0)

static void packet_set(NX_PACKET *packet, UCHAR *data, ULONG length)
{
    memset(packet, 0, sizeof(*packet));
    packet->nx_packet_prepend_ptr = data;
    packet->nx_packet_append_ptr = data + length;
    packet->nx_packet_length = length;
}

static int test_cursor(void)
{
    NX_PACKET parts[16];
    NX_PACKET *fragment = NX_NULL;
    ULONG base = 0, moved, expected_moved, offset, want;
    UCHAR data[256], out[300], expected[300];
    unsigned i;
    UINT status, expected_status;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (UCHAR)i;
    for (i = 0; i < 16; i++)
    {
        packet_set(&parts[i], data + i * 16, 16);
        parts[i].nx_packet_next = (i < 15) ? &parts[i + 1] : NX_NULL;
    }
    parts[0].nx_packet_length = sizeof(data);

    /* Repeated small reads, including fragment crossings and an exact end. */
    for (offset = 0; offset < sizeof(data); offset += moved)
    {
        want = sizeof(data) - offset;
        if (want > 7)
            want = 7;
        CHECK(bsd_packet_extract_cached(parts, offset, out, want, &moved,
                                         &fragment, &base) == NX_SUCCESS);
        CHECK(moved == want && memcmp(out, data + offset, want) == 0);
        CHECK(fragment == &parts[(offset + want - 1) / 16]);
        CHECK(base == ((offset + want - 1) / 16) * 16);
    }

    /* Backwards seeks and every boundary/oversize combination agree with
       the native implementation, including unchanged counts on errors. */
    for (offset = 258; ; offset--)
    {
        for (want = 0; want <= 273; want += 13)
        {
            memset(out, 0xa5, sizeof(out));
            memset(expected, 0xa5, sizeof(expected));
            moved = expected_moved = 999;
            expected_status = nx_packet_data_extract_offset(parts, offset,
                                        expected, want, &expected_moved);
            status = bsd_packet_extract_cached(parts, offset, out, want,
                                               &moved, &fragment, &base);
            CHECK(status == expected_status && moved == expected_moved);
            CHECK(memcmp(out, expected, sizeof(out)) == 0);
        }
        if (offset == 0)
            break;
    }

    /* Empty middle fragments, plus a logically shorter final fragment. */
    parts[5].nx_packet_append_ptr = parts[5].nx_packet_prepend_ptr;
    parts[0].nx_packet_length = 233;
    fragment = NX_NULL;
    for (offset = 0; offset < 233; offset += moved)
    {
        want = (233 - offset < 17) ? 233 - offset : 17;
        CHECK(nx_packet_data_extract_offset(parts, offset, expected, want,
                                            &expected_moved) == NX_SUCCESS);
        CHECK(bsd_packet_extract_cached(parts, offset, out, want, &moved,
                                         &fragment, &base) == NX_SUCCESS);
        CHECK(moved == expected_moved && memcmp(out, expected, moved) == 0);
    }

    /* Short physical chains retain even the native extractor's count
       semantics (it reports the logical request, including its absent tail). */
    parts[0].nx_packet_length = 256;
    parts[3].nx_packet_next = NX_NULL;
    fragment = NX_NULL;
    memset(out, 0xa5, sizeof(out));
    memset(expected, 0xa5, sizeof(expected));
    CHECK(nx_packet_data_extract_offset(parts, 48, expected, 40,
                                        &expected_moved) == NX_SUCCESS);
    CHECK(bsd_packet_extract_cached(parts, 48, out, 40, &moved,
                                     &fragment, &base) == NX_SUCCESS);
    CHECK(moved == expected_moved && memcmp(out, expected, sizeof(out)) == 0);
    CHECK(fragment == NX_NULL);

    /* Reuse the head address for another chain, with an explicit owner reset. */
    parts[0].nx_packet_length = 32;
    parts[1].nx_packet_next = NX_NULL;
    fragment = NX_NULL;
    base = 192;                         /* ignored with no cached fragment */
    CHECK(bsd_packet_extract_cached(parts, 0, out, 32, &moved,
                                     &fragment, &base) == NX_SUCCESS);
    CHECK(moved == 32 && memcmp(out, data, 32) == 0);
    CHECK(fragment == &parts[1] && base == 16);
    return 0;
}

int main(void)
{
    static const UCHAR first_data[] = "abcdefgh";
    static const UCHAR second_data[] = "ijklmnop";
    NX_PACKET first;
    NX_PACKET second;
    UCHAR out[16];
    ULONG moved;
    UINT status;

    packet_set(&first, (UCHAR *)(VOID *)first_data, 8UL);
    memset(out, 0, sizeof(out));
    moved = 99UL;
    status = bsd_packet_extract(&first, 0UL, out, 4UL, &moved);
    CHECK(status == NX_SUCCESS);
    CHECK(moved == 4UL);
    CHECK(memcmp(out, "abcd", 4) == 0);

    /* A nonzero offset ending exactly at the logical end is valid. */
    memset(out, 0, sizeof(out));
    moved = 99UL;
    status = bsd_packet_extract(&first, 4UL, out, 4UL, &moved);
    CHECK(status == NX_SUCCESS);
    CHECK(moved == 4UL);
    CHECK(memcmp(out, "efgh", 4) == 0);

    /* But the offset itself may not equal the end of a nonempty packet,
       including a zero-byte request.  This is the native NetX boundary. */
    moved = 99UL;
    status = bsd_packet_extract(&first, 8UL, out, 0UL, &moved);
    CHECK(status == NX_PACKET_OFFSET_ERROR);
    CHECK(moved == 99UL);

    /* A request crossing fragments must use the generic chain walk. */
    packet_set(&second, (UCHAR *)(VOID *)second_data, 8UL);
    first.nx_packet_next = &second;
    first.nx_packet_length = 16UL;
    memset(out, 0, sizeof(out));
    moved = 99UL;
    status = bsd_packet_extract(&first, 6UL, out, 6UL, &moved);
    CHECK(status == NX_SUCCESS);
    CHECK(moved == 6UL);
    CHECK(memcmp(out, "ghijkl", 6) == 0);

    /* Physical and logical lengths are independent invariants.  If they do
       not agree, the shortcut must not copy bytes beyond the logical packet. */
    first.nx_packet_next = NX_NULL;
    first.nx_packet_length = 4UL;
    memset(out, 0xA5, sizeof(out));
    moved = 99UL;
    status = bsd_packet_extract(&first, 0UL, out, 8UL, &moved);
    CHECK(status == NX_SUCCESS);
    CHECK(moved == 4UL);
    CHECK(memcmp(out, "abcd", 4) == 0);
    CHECK(out[4] == 0xA5);

    CHECK(bsd_packet_length(&first) == 4UL);
    CHECK(bsd_packet_length(NX_NULL) == 0UL);

    CHECK(test_cursor() == 0);
    puts("packet extract: single buffer, cached chains and native equivalence");
    return 0;
}
