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

/*
 * The line of `buf` where the DEFAULT gateway is first set, or 0.  Must mirror
 * cfg_parse_routes()'s default handling, because a routes/default_gateway file
 * sets the default three ways and a keyword grep finds none of the other two:
 * a bare GATEWAY=<addr> (no DESTINATION on the same line), DEFAULT=<addr>, or
 * DEFAULTGATEWAY=<addr>.  A GATEWAY on a line that also carries a DESTINATION
 * is a specific route and does not set the default; VIA never does.  The
 * loader reads DEVS:Internet/default_gateway then DEVS:Internet/routes and the
 * first line to set the default wins, so the caller asks the first file, then
 * the second, and takes the first nonzero answer (F-158).  `buf` is split in
 * place, like every caller of ami_cfg_next_line().
 */
ULONG ami_cfg_default_gateway_line(char *buf)
{
    char  *cursor = buf;
    char  *line;
    ULONG  lineno = 0;

    if (buf == NULL)
        return 0;

    while ((line = ami_cfg_next_line(&cursor)) != NULL)
    {
        char *pos;
        char *key;
        char *value;
        ULONG gateway    = 0;
        BOOL  have_gw    = FALSE;
        BOOL  gw_spelled = FALSE;
        BOOL  have_dst   = FALSE;
        BOOL  is_default = FALSE;

        lineno++;

        ami_cfg_strip_comment(line, "#;");
        line = ami_cfg_trim(line);
        if (*line == '\0')
            continue;

        pos = line;
        while (ami_cfg_next_pair(&pos, &key, &value))
        {
            if (ami_cfg_stricmp(key, "gateway") == 0 ||
                ami_cfg_stricmp(key, "via") == 0)
            {
                if (ami_config_parse_ip(value, &gateway) && gateway != 0UL)
                {
                    have_gw = TRUE;
                    if (ami_cfg_stricmp(key, "gateway") == 0)
                        gw_spelled = TRUE;
                }
            }
            else if (ami_cfg_stricmp(key, "default") == 0 ||
                     ami_cfg_stricmp(key, "defaultgateway") == 0)
            {
                is_default = TRUE;
                if (*value != '\0' && ami_config_parse_ip(value, &gateway) &&
                    gateway != 0UL)
                    have_gw = TRUE;
            }
            else if (ami_cfg_stricmp(key, "dst") == 0 ||
                     ami_cfg_stricmp(key, "destination") == 0 ||
                     ami_cfg_stricmp(key, "hostdst") == 0 ||
                     ami_cfg_stricmp(key, "hostdestination") == 0 ||
                     ami_cfg_stricmp(key, "netdst") == 0 ||
                     ami_cfg_stricmp(key, "netdestination") == 0)
            {
                have_dst = TRUE;
            }
        }

        if (is_default)
        {
            if (have_gw)
                return lineno;
        }
        else if (!have_dst && have_gw && gw_spelled)
        {
            return lineno;
        }
    }

    return 0;
}

ULONG ami_cfg_default_gateway_line_file(const char *path)
{
    char  *buf = (char *)ami_cfg_read_file(path, NULL);
    ULONG  found;

    if (buf == NULL)
        return 0;

    found = ami_cfg_default_gateway_line(buf);
    ami_free(buf);

    return found;
}

/*
 * The line of `buf` whose GATEWAY the interface parser keeps as `want`, or 0.
 * Must mirror ami_cfg_parse_interface()'s IF_KEY_GATEWAY case, where a GATEWAY
 * whose value parses overwrites out->gateway each time, so the LAST parseable
 * value wins: an earlier GATEWAY -- valid or not -- is overwritten or left
 * alone.  A plain keyword search would name the first GATEWAY line, which may
 * be an invalid value the parser skipped (F-158).  The kept value is the last
 * parseable one, so when that is not `want` (the file changed between load and
 * diagnosis) the answer is 0, not the line of an overwritten earlier value.
 * `buf` is split in place, like every caller of ami_cfg_next_line().
 */
ULONG ami_cfg_interface_gateway_line(char *buf, ULONG want)
{
    char  *cursor = buf;
    char  *line;
    ULONG  lineno = 0;
    ULONG  accepted_line = 0;
    ULONG  accepted_val  = 0;
    BOOL   have_accepted = FALSE;

    if (buf == NULL)
        return 0;

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
            ULONG ip;

            if (ami_cfg_stricmp(key, "gateway") != 0)
                continue;

            if (ami_config_parse_ip(value, &ip))
            {
                accepted_line = lineno;         /* last accepted wins, as IF_KEY_GATEWAY */
                accepted_val  = ip;
                have_accepted = TRUE;
            }
        }
    }

    return (have_accepted && accepted_val == want) ? accepted_line : 0;
}

ULONG ami_cfg_interface_gateway_line_file(const char *path, ULONG want)
{
    char  *buf = (char *)ami_cfg_read_file(path, NULL);
    ULONG  found;

    if (buf == NULL)
        return 0;

    found = ami_cfg_interface_gateway_line(buf, want);
    ami_free(buf);

    return found;
}

/*
 * TRUE when `name` sits at the parser's interface-name ceiling, so it may be a
 * longer filename truncated to AMI_CFG_IFNAME_MAX characters.  A reconstructed
 * DEVS:NetInterfaces/<name> path then cannot be trusted to be the file the
 * loader read, because the loader read the ORIGINAL name (F-158).
 */
BOOL ami_cfg_ifname_may_be_truncated(const char *name)
{
    return name != NULL && ami_cfg_strlen(name) >= AMI_CFG_IFNAME_MAX;
}

/*
 * The 1-based line of `buf` whose NAMESERVER the resolver parser keeps as
 * `want`, counted as the parser counts lines, or 0.  Mirrors
 * ami_cfg_parse_resolver()'s NAMESERVER case: the first key=value pair on a
 * line must spell NAMESERVER (case-insensitive) and its value must parse as an
 * IP; the parser keeps each such line in order up to AMI_CFG_MAX_NAMESERVERS.
 * Returns the first line whose parsed value equals `want`, so a diagnostic
 * names the exact line the loader took (F-158).  `buf` is a whole file's text,
 * split in place, like every caller of ami_cfg_next_line().
 */
ULONG ami_cfg_nameserver_line(char *buf, ULONG want)
{
    char  *cursor = buf;
    char  *line;
    ULONG  lineno = 0;

    if (buf == NULL)
        return 0;

    while ((line = ami_cfg_next_line(&cursor)) != NULL)
    {
        char *pos;
        char *key;
        char *value;
        ULONG ip;

        lineno++;

        ami_cfg_strip_comment(line, "#;");
        line = ami_cfg_trim(line);
        if (*line == '\0')
            continue;

        /* The resolver parser takes only the first pair on a line. */
        pos = line;
        if (!ami_cfg_next_pair(&pos, &key, &value))
            continue;

        if (ami_cfg_stricmp(key, "nameserver") != 0)
            continue;

        if (ami_config_parse_ip(value, &ip) && ip == want)
            return lineno;
    }

    return 0;
}

ULONG ami_cfg_nameserver_line_file(const char *path, ULONG want)
{
    char  *buf = (char *)ami_cfg_read_file(path, NULL);
    ULONG  found;

    if (buf == NULL)
        return 0;

    found = ami_cfg_nameserver_line(buf, want);
    ami_free(buf);

    return found;
}
