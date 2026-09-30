/*
 * The IPv6 routing-table selector must keep a failed query apart from an
 * empty table (F-202).  tool_routes6() used to return 0 for both, so arp set
 * have_routes6 = TRUE on a selector the library does not know, and off_link6()
 * then asserted an address is off-link with no route data behind it.  This
 * reads the two sources and locks the corrected control flow.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef AMINETXDUO_SOURCE_DIR
#define AMINETXDUO_SOURCE_DIR "."
#endif

static const char *source_dir(void)
{
    const char *env = getenv("AMINETXDUO_SOURCE_DIR");

    return (env != NULL && env[0] != '\0') ? env : AMINETXDUO_SOURCE_DIR;
}

static int failures;
static int checks;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                    \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

static char *slurp(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long  n;
    char *buf;

    if (fp == NULL)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    n = ftell(fp);
    if (n < 0) { fclose(fp); return NULL; }
    rewind(fp);
    buf = malloc((size_t)n + 1);
    if (buf == NULL) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) { free(buf); fclose(fp); return NULL; }
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Comments and string literals out, so a sentence that NAMES a call is not
   read as the call. */
static void code_only(char *s)
{
    char *r = s;
    char *w = s;

    while (*r != '\0') {
        if (r[0] == '/' && r[1] == '*') {
            r += 2;
            while (*r != '\0' && !(r[0] == '*' && r[1] == '/'))
                r++;
            if (*r != '\0')
                r += 2;
            *w++ = ' ';
            continue;
        }
        if (r[0] == '/' && r[1] == '/') {
            while (*r != '\0' && *r != '\n')
                r++;
            continue;
        }
        if (*r == '"' || *r == '\'') {
            char q = *r++;

            while (*r != '\0' && *r != q) {
                if (*r == '\\' && r[1] != '\0')
                    r++;
                r++;
            }
            if (*r != '\0')
                r++;
            *w++ = q;
            *w++ = q;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static int ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* How many times `name` appears as a whole identifier. */
static int uses(const char *code, const char *name)
{
    const char *p = code;
    size_t      n = strlen(name);
    int         count = 0;

    while ((p = strstr(p, name)) != NULL) {
        if ((p == code || !ident_char(p[-1])) && !ident_char(p[n]))
            count++;
        p += n;
    }
    return count;
}

static char *read_code(const char *rel)
{
    char  path[1024];
    char *src;

    snprintf(path, sizeof(path), "%s/%s", source_dir(), rel);
    src = slurp(path);
    CHECK(src != NULL, "cannot read %s", path);
    if (src != NULL)
        code_only(src);
    return src;
}

/* The body of `signature`, braces matched, or NULL. */
static char *function_body(const char *code, const char *signature)
{
    const char *p = strstr(code, signature);
    const char *open;
    int         depth = 0;
    const char *q;
    char       *body;

    if (p == NULL || (open = strchr(p, '{')) == NULL)
        return NULL;

    for (q = open; *q != '\0'; q++) {
        if (*q == '{')
            depth++;
        else if (*q == '}' && --depth == 0)
            break;
    }
    if (*q == '\0')
        return NULL;

    body = malloc((size_t)(q - open) + 2);
    if (body == NULL)
        return NULL;
    memcpy(body, open, (size_t)(q - open) + 1);
    body[q - open + 1] = '\0';
    return body;
}

int main(void)
{
    char *code = read_code("src/tools/tool_nx.c");
    char *body;

    if (code != NULL) {
        body = function_body(code, "LONG tool_routes6(ToolRoutes6 *out)");
        CHECK(body != NULL, "tool_nx.c has tool_routes6()");
        if (body != NULL) {
            /* A failed selector (-1) is closed and returned, not folded into
               the empty-table 0.  The three failure returns are the null
               out, the unopened library, and the failed query. */
            CHECK(uses(body, "if (n < 0)") == 1,
                  "the query return is checked before assuming empty");
            CHECK(uses(body, "tool_netstatus_close") == 2,
                  "the base is closed on the failed path as well");
            CHECK(uses(body, "return -1") == 3,
                  "three failure returns: null out, no library, failed query");
            CHECK(uses(body, "return 0") == 1,
                  "one success return, for a genuine (possibly empty) table");
            free(body);
        }
        free(code);
    }

    code = read_code("src/tools/arp.c");
    if (code != NULL) {
        body = function_body(code,
                             "static BOOL off_link6(const ULONG addr[4], "
                             "BOOL have_routes)");
        CHECK(body != NULL, "arp.c has off_link6()");
        if (body != NULL) {
            /* The guard that makes the return value matter: no routes known,
               no off-link assertion. */
            CHECK(uses(body, "if (!have_routes)") == 1,
                  "off_link6 declines when routes are unknown");
            CHECK(uses(body, "return TRUE") == 1,
                  "off-link is asserted only past the guard");
            free(body);
        }
        free(code);
    }

    if (failures != 0) {
        printf("%d checks, %d failure(s)\n", checks, failures);
        return 1;
    }
    printf("%d checks, 0 failures\n", checks);
    return 0;
}
