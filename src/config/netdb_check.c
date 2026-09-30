/*
 * AmiNetXDuo, one line of a DEVS:Internet netdb file as the loader sees it.
 *
 * CheckNetConfig had a grammar of its own for these files, and it drifted from
 * netdb.c's (F-094): no networks file, hex numbers and '#' mid-word called
 * broken, out-of-range protocols and ports called fine, a malformed AmiTCP
 * HOST line and any service named domain or host not looked at.  This is the
 * loader's acceptance, step for step, so the checker says what the loader
 * does.  netdb.c is left as it is; test_config holds the two together.
 *
 * Not linked into bsdsocket.library: nothing there calls it.
 *
 * SPDX-License-Identifier: MIT
 */

#include "config_internal.h"

#define NETDB_CHECK_LINE    256
#define NETDB_CHECK_TOKENS  34      /* netdb.c's AMI_NETDB_MAX_TOKENS */

static VOID netdb_check_word(char *word, ULONG wordlen, const char *text)
{
    if (word != NULL && wordlen > 0)
        ami_cfg_copy_string(word, wordlen, text);
}

/*
 * NAMESERVER=... as well as NAMESERVER ...  Never reads past the token: its
 * terminator cannot equal a keyword letter, so a shorter token returns FALSE
 * at its own '\0', and token[n] is read only once n letters have matched.
 */
static BOOL netdb_check_keyword(const char *token, const char *keyword)
{
    ULONG n = ami_cfg_strlen(keyword);
    ULONG i;

    for (i = 0; i < n; i++)
    {
        char a = token[i];
        char b = keyword[i];

        if (a >= 'a' && a <= 'z')
            a = (char)(a - 'a' + 'A');
        if (a != b)
            return FALSE;
    }

    return (BOOL)(token[n] == '\0' || token[n] == '=');
}

/* What ami_config_load() reads out of the hosts file, and netdb.c skips. */
static BOOL netdb_check_resolver(const char *token)
{
    return (BOOL)(netdb_check_keyword(token, "NAMESERVER") ||
                  netdb_check_keyword(token, "DOMAIN") ||
                  netdb_check_keyword(token, "SEARCH") ||
                  netdb_check_keyword(token, "HOSTNAME"));
}

UWORD ami_netdb_line_verdict(UWORD kind, const char *text, char *word,
                             ULONG wordlen)
{
    char   buf[NETDB_CHECK_LINE];
    char  *tokens[NETDB_CHECK_TOKENS];
    char  *line;
    ULONG  count;
    ULONG  value;

    netdb_check_word(word, wordlen, "");

    ami_cfg_copy_string(buf, sizeof(buf), text);
    ami_cfg_strip_comment(buf, "#");
    line = ami_cfg_trim(buf);
    while (*line != '\0' && (line[ami_cfg_strlen(line) - 1] == '\n'))
        line[ami_cfg_strlen(line) - 1] = '\0';
    line = ami_cfg_trim(line);
    if (*line == '\0')
        return AMI_NETDB_LINE_SKIP;

    count = ami_cfg_tokenize(line, tokens, NETDB_CHECK_TOKENS);

    if (kind == AMI_NETDB_HOSTS)
    {
        char **row = tokens;

        if (count == 0)
            return AMI_NETDB_LINE_SKIP;

        if (ami_cfg_stricmp(row[0], "host") == 0)
        {
            /* AmiTCP netdb-myhost: HOST <address> <name> [alias...]. */
            if (count < 3)
                return AMI_NETDB_LINE_SHORT;
            if (!ami_config_parse_ip(row[1], &value))
            {
                netdb_check_word(word, wordlen, row[1]);
                return AMI_NETDB_LINE_BAD;
            }
            return AMI_NETDB_LINE_ENTRY;
        }

        if (!ami_config_parse_ip(row[0], &value))
        {
            if (netdb_check_resolver(row[0]))
                return AMI_NETDB_LINE_SKIP;
            netdb_check_word(word, wordlen, row[0]);
            return AMI_NETDB_LINE_BAD;
        }

        return (count < 2) ? AMI_NETDB_LINE_SHORT : AMI_NETDB_LINE_ENTRY;
    }

    if (count < 2)
        return AMI_NETDB_LINE_SHORT;

    netdb_check_word(word, wordlen, tokens[1]);

    switch (kind)
    {
    case AMI_NETDB_NETWORKS:
        if (!ami_cfg_parse_net_number(tokens[1], &value))
            return AMI_NETDB_LINE_BAD;
        break;

    case AMI_NETDB_PROTOCOLS:
        if (!ami_cfg_parse_ulong(tokens[1], &value) || value > 255UL)
            return AMI_NETDB_LINE_BAD;
        break;

    case AMI_NETDB_SERVICES:
    {
        char *slash = tokens[1];

        while (*slash != '\0' && *slash != '/')
            slash++;
        if (*slash != '/' || slash[1] == '\0')
            return AMI_NETDB_LINE_BAD;

        *slash = '\0';
        if (!ami_cfg_parse_ulong(tokens[1], &value) || value > 65535UL)
            return AMI_NETDB_LINE_BAD;
        break;
    }

    default:
        return AMI_NETDB_LINE_SKIP;
    }

    netdb_check_word(word, wordlen, "");
    return AMI_NETDB_LINE_ENTRY;
}
