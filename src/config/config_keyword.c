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
