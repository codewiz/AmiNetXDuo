/*
 * AmiNetXDuo, which line of a configuration file a keyword is on, counted as
 * the parser counts lines.  For CheckNetConfig (F-159).
 *
 * A file of its own so that bsdsocket.library, which links the rest of this
 * archive but calls nothing here, never pulls it in.
 *
 * SPDX-License-Identifier: MIT
 */

#include "config_internal.h"
#include "aminetxduo/compat.h"

/*
 * The 1-based line of `buf` whose first word is `keyword` -- case aside, and
 * followed by the end, '=', a space or a tab -- or 0.  Lines are split by
 * ami_cfg_next_line(), so the number is the one the parser counts: no line
 * length limit, and CR, LF, CRLF and LFCR each end one line (F-159).  `buf`
 * is split in place.
 */
ULONG ami_cfg_keyword_line(char *buf, const char *keyword)
{
    char  *cursor = buf;
    char  *line;
    ULONG  lineno = 0;
    ULONG  n      = ami_cfg_strlen(keyword);

    while ((line = ami_cfg_next_line(&cursor)) != NULL)
    {
        ULONG i;

        lineno++;

        while (*line == ' ' || *line == '\t')
            line++;

        /* Never past the line: its NUL cannot equal a keyword character, so
           a shorter line stops the loop there, and line[n] is read only
           after n characters matched. */
        for (i = 0; i < n; i++)
        {
            char a = line[i];
            char b = keyword[i];

            if (a >= 'a' && a <= 'z')
                a = (char)(a - 'a' + 'A');
            if (b >= 'a' && b <= 'z')
                b = (char)(b - 'a' + 'A');
            if (a != b)
                break;
        }

        if (i == n && (line[n] == '\0' || line[n] == '=' ||
                       line[n] == ' '  || line[n] == '\t'))
            return lineno;
    }

    return 0;
}

ULONG ami_cfg_keyword_line_file(const char *path, const char *keyword)
{
    char  *buf = (char *)ami_cfg_read_file(path, NULL);
    ULONG  found;

    if (buf == NULL)
        return 0;

    found = ami_cfg_keyword_line(buf, keyword);
    ami_free(buf);

    return found;
}

/* The line of the `occur`-th ADDRESS6 entry the parser keeps.  Must mirror
   ami_cfg_parse_interface()'s IF_KEY_ADDRESS6 case -- the keyword ADDRESS6 or
   its IPADDRESS6 alias, a value that parses, a "%zone" that is empty or names
   this interface, and the address still under AMI_CFG_MAX_ADDRESS6 -- or a
   rejected earlier line with the same value would be named instead (F-158).
   `buf` is split in place, like every caller of ami_cfg_next_line(). */
ULONG ami_cfg_address6_line(char *buf, const char *ifname,
                            const ULONG want[AMI_CFG_IP6_WORDS], UWORD occur)
{
    char  *cursor = buf;
    char  *line;
    ULONG  lineno = 0;
    ULONG  kept = 0;      /* ADDRESS6 entries the parser kept, any value */

    while ((line = ami_cfg_next_line(&cursor)) != NULL)
    {
        char *pos;
        char *key;
        char *value;

        lineno++;

        ami_cfg_strip_comment(line, "#;");
        line = ami_cfg_trim(line);
        if (*line == '\0')
            continue;

        pos = line;
        while (ami_cfg_next_pair(&pos, &key, &value))
        {
            if (ami_cfg_stricmp(key, "address6") != 0 &&
                ami_cfg_stricmp(key, "ipaddress6") != 0)
                continue;

            {
                ULONG addr[AMI_CFG_IP6_WORDS];
                ULONG prefix = 64;
                char  zone[AMI_CFG_IP6_ZONE_LEN];

                if (!ami_config_parse_ip6_zone(value, addr, &prefix, zone,
                                               sizeof(zone)))
                    continue;                   /* bad value: not taken */
                if (zone[0] != '\0' &&
                    (ifname == NULL || ami_cfg_stricmp(zone, ifname) != 0))
                    continue;                   /* foreign zone: not taken */
                if (kept >= AMI_CFG_MAX_ADDRESS6)
                    continue;                   /* past the stack's ceiling */

                kept++;

                if (addr[0] == want[0] && addr[1] == want[1] &&
                    addr[2] == want[2] && addr[3] == want[3])
                {
                    if (occur == 0)
                        return lineno;
                    occur--;
                }
            }
        }
    }

    return 0;
}

ULONG ami_cfg_address6_line_file(const char *path, const char *ifname,
                                 const ULONG want[AMI_CFG_IP6_WORDS],
                                 UWORD occur)
{
    char  *buf = (char *)ami_cfg_read_file(path, NULL);
    ULONG  found;

    if (buf == NULL)
        return 0;

    found = ami_cfg_address6_line(buf, ifname, want, occur);
    ami_free(buf);

    return found;
}
