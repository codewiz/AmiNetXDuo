/*
 * nslookup's TXT decoding, kept apart so the host can test it.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_NSLTXT_H
#define AMINETXDUO_NSLTXT_H

/* What a terminal is shown of one byte: control codes become '?'. */
static inline char nsl_safe_char(unsigned char c)
{
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f))
        return '?';

    return (char)c;
}

/*
 * A TXT record's length-prefixed strings from msg[p] up to msg[end], joined
 * into out (outlen >= 1), which always ends in NUL.  *omitted is the number
 * of bytes that did not fit (F-171): a caller must say so rather than print
 * a cut-off record as if it were whole.  0 when a string runs past end.
 */
static inline int nsl_txt_join(const unsigned char *msg, unsigned long p,
                               unsigned long end, char *out,
                               unsigned long outlen, unsigned long *omitted)
{
    unsigned long o = 0;

    *omitted = 0;

    while (p < end)
    {
        unsigned long n = (unsigned long)msg[p++];
        unsigned long i;

        if (p + n > end)
            return 0;

        for (i = 0; i < n; i++)
        {
            if (o + 1 < outlen)
                out[o++] = nsl_safe_char(msg[p + i]);
            else
                (*omitted)++;
        }

        p += n;
    }

    out[o] = '\0';
    return 1;
}

#endif
