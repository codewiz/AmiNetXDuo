/*
 * F-300: the trust store's root read inside the handshake takes the index and
 * the certificate from one open.  tls_store_open() indexes store A; the file
 * at that path is then replaced by store B, the documented update being
 * `copy certificates DEVS:Internet/certificates`; tls_store_fetch() must not
 * read A's offsets out of B's bytes.  The stores are real ACS1 files on disk
 * and the certificate bytes are opaque here: the fetch does not parse them.
 *
 * NOT covered, and not fixed by this: two stores with an identical index and
 * different certificate bytes at equal length still look the same (F-300 D2).
 *
 * SPDX-License-Identifier: MIT
 */

#include "tls_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

/* ------------------------------------------------------------ the host -- */

APTR AllocVec(ULONG size, ULONG requirements)
{
    (VOID)requirements;
    return calloc(1, size);
}

VOID FreeVec(APTR memory) { free(memory); }

static struct Library h_library;
struct Library *OpenLibrary(STRPTR name, ULONG version)
{ (VOID)name; (VOID)version; return &h_library; }
VOID CloseLibrary(struct Library *library) { (VOID)library; }
VOID ami_tls_timer_close(VOID);
VOID ami_tls_timer_close(VOID) { }
VOID Delay(LONG ticks) { (VOID)ticks; }
VOID Forbid(VOID) { }
VOID Permit(VOID) { }
VOID ObtainSemaphore(struct SignalSemaphore *sem) { (VOID)sem; }
VOID ReleaseSemaphore(struct SignalSemaphore *sem) { (VOID)sem; }
int ami_random_rand(void) { return 1; }

BPTR Open(STRPTR name, LONG mode)
{
    return (BPTR)fopen((const char *)name, (mode == MODE_NEWFILE) ? "wb" : "rb");
}

VOID Close(BPTR fh)
{
    if (fh != (BPTR)0)
        fclose((FILE *)fh);
}

LONG Read(BPTR fh, APTR buffer, LONG length)
{
    return (LONG)fread(buffer, 1, (size_t)length, (FILE *)fh);
}

LONG Write(BPTR fh, const void *buffer, LONG length)
{
    return (LONG)fwrite(buffer, 1, (size_t)length, (FILE *)fh);
}

LONG Seek(BPTR fh, LONG position, LONG mode)
{
    long was = ftell((FILE *)fh);

    (VOID)mode;                         /* OFFSET_BEGINNING only */
    if (fseek((FILE *)fh, position, SEEK_SET) != 0)
        return -1;
    return (LONG)was;
}

/* tls_store.c's handshake hook links against these; the fetch this test
   drives calls none of them, and a build without section GC (the sanitize
   arm) still needs them defined. */
UINT _nx_secure_remote_certificate_verify(NX_SECURE_X509_CERTIFICATE_STORE *store,
                                          NX_SECURE_X509_CERT *certificate,
                                          ULONG current_time)
{ (VOID)store; (VOID)certificate; (VOID)current_time; return 1; }

UINT _nx_secure_x509_asn1_tlv_block_parse(const UCHAR *buffer, ULONG *buffer_length,
                                          USHORT *tlv_type, USHORT *tlv_tag_class,
                                          ULONG *tlv_length, const UCHAR **tlv_data,
                                          ULONG *header_length)
{
    (VOID)buffer; (VOID)buffer_length; (VOID)tlv_type; (VOID)tlv_tag_class;
    (VOID)tlv_length; (VOID)tlv_data; (VOID)header_length;
    return 1;
}

UINT _nx_secure_x509_store_certificate_add(NX_SECURE_X509_CERT *certificate,
                                           NX_SECURE_X509_CERTIFICATE_STORE *store,
                                           UINT location)
{ (VOID)certificate; (VOID)store; (VOID)location; return 1; }

UINT _nx_secure_x509_certificate_initialize(NX_SECURE_X509_CERT *certificate,
                                            UCHAR *certificate_data, USHORT length,
                                            UCHAR *raw_data_buffer, USHORT buffer_size,
                                            const UCHAR *private_key,
                                            USHORT priv_len, UINT private_key_type)
{
    (VOID)certificate; (VOID)certificate_data; (VOID)length;
    (VOID)raw_data_buffer; (VOID)buffer_size; (VOID)private_key;
    (VOID)priv_len; (VOID)private_key_type;
    return 1;
}

/* ---------------------------------------------------------- the stores -- */

typedef struct
{
    ULONG       key;
    const char *der;                    /* opaque bytes, NUL-terminated */
} Root;

static void put32(unsigned char *p, ULONG v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* An ACS1 store as tools/mkcertstore.py writes it; roots sorted by key. */
static void write_store(const char *path, const Root *roots, int n)
{
    unsigned char buf[4096];
    ULONG         data = 16UL + 12UL * (ULONG)n;
    ULONG         off  = data;
    size_t        len  = data;
    FILE         *fh;
    int           i;

    memcpy(buf, "ACS1", 4);
    put32(buf + 4, (ULONG)n);
    put32(buf + 8, 16);
    put32(buf + 12, data);
    for (i = 0; i < n; i++)
    {
        ULONG l = (ULONG)strlen(roots[i].der);

        put32(buf + 16 + 12 * i, roots[i].key);
        put32(buf + 20 + 12 * i, off);
        put32(buf + 24 + 12 * i, l);
        memcpy(buf + off, roots[i].der, l);
        off += l;
        len += l;
    }

    fh = fopen(path, "wb");
    fwrite(buf, 1, len, fh);
    fclose(fh);
}

static const Root store_a[] = {
    { 0x20000000UL, "AAAA-root-two-der" },
    { 0x30000000UL, "AAAA-root-three-der-bytes" },
};

/* A with one root added in front: every offset moves by 12 + its length. */
static const Root store_b[] = {
    { 0x10000000UL, "BBBB-new-root" },
    { 0x20000000UL, "BBBB-root-two-der" },
    { 0x30000000UL, "BBBB-root-three-der-bytes" },
};

/* A with root three replaced by a longer one: same count, other offsets. */
static const Root store_c[] = {
    { 0x20000000UL, "AAAA-root-two-der" },
    { 0x30000000UL, "CCCC-root-three-der-bytes-longer" },
};

int main(void)
{
    char     path[] = "/tmp/test_tls_store_XXXXXX";
    int      fd     = mkstemp(path);
    TLSStore store;
    UCHAR    der[256];
    ULONG    n;

    DOSBase = (struct DosLibrary *)1;   /* tls_runtime.c's; never called through */

    if (fd < 0)
    {
        printf("FAIL no temporary file\n");
        return 1;
    }
    close(fd);

    /* The file unchanged since TLSOpen(): each root is its own bytes. */
    memset(&store, 0, sizeof(store));
    write_store(path, store_a, 2);
    CHECK(tls_store_open(&store, path) == TLS_OK);
    memset(der, 0, sizeof(der));
    n = tls_store_test_fetch(&store, 0x30000000UL, der, sizeof(der));
    CHECK(n == strlen(store_a[1].der));
    CHECK(memcmp(der, store_a[1].der, n) == 0);
    n = tls_store_test_fetch(&store, 0x20000000UL, der, sizeof(der));
    CHECK(n == strlen(store_a[0].der) && memcmp(der, store_a[0].der, n) == 0);
    CHECK(tls_store_test_fetch(&store, 0x40000000UL, der, sizeof(der)) == 0);

    /* THE CASE: A indexed, B copied over it, then the handshake's read.
       Nothing is loaded: not A's offsets over B's bytes. */
    write_store(path, store_b, 3);
    memset(der, 0, sizeof(der));
    n = tls_store_test_fetch(&store, 0x30000000UL, der, sizeof(der));
    CHECK(n == 0);
    CHECK(der[0] == 0);                 /* and nothing was written */

    /* The same count, a root replaced by a longer one. */
    write_store(path, store_c, 2);
    CHECK(tls_store_test_fetch(&store, 0x30000000UL, der, sizeof(der)) == 0);

    /* A written back: the snapshot matches again and the read works. */
    write_store(path, store_a, 2);
    n = tls_store_test_fetch(&store, 0x30000000UL, der, sizeof(der));
    CHECK(n == strlen(store_a[1].der) && memcmp(der, store_a[1].der, n) == 0);

    /* The file gone. */
    unlink(path);
    CHECK(tls_store_test_fetch(&store, 0x30000000UL, der, sizeof(der)) == 0);

    tls_store_close(&store);

    printf("RESULT tls_store checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
