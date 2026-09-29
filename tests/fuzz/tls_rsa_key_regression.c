/*
 * F-276: the RSA prime table in src/tls/ami_tls_crypto.c points into each
 * server's own key buffers.  Two servers loaded from the same key file have
 * equal moduli; a lookup by the modulus BYTES handed one of them primes inside
 * the other's buffer, and those were freed when the other closed while this
 * one kept signing.  The lookup is by the certificate's own pointers now, and
 * a closing certificate drops only its own entry.
 *
 * Two certificates from separate copies of the same DER:
 *   - each signs with CRT while registered, and the results agree;
 *   - A forgotten and its buffers overwritten and freed, B still signs with
 *     CRT and gets the same signature;
 *   - a third copy never registered signs WITHOUT CRT (no byte-match borrow);
 *   - B forgotten, B signs without CRT.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nx_secure_tls.h"
#include "nx_secure_x509.h"
#include "ami_tls_crypto.h"
#include "tls.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "tls_test_certs.h"
#pragma GCC diagnostic pop

/* timer.device, which the counters' timing reads. */
BOOL  ami_tls_timer_is_open(VOID)          { return 0; }
ULONG ami_tls_eclock(VOID)                 { return 0; }
ULONG ami_tls_eclock_micros(ULONG ticks)   { return ticks; }

#define SIG_BYTES   256

static int checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

typedef struct
{
    NX_SECURE_X509_CERT cert;
    UCHAR              *der;
    UCHAR              *key;
} Server;

static const NX_CRYPTO_METHOD *rsa;
static UCHAR                  *rsa_metadata;
static ULONG                   rsa_metadata_size;

static const NX_CRYPTO_METHOD *suite_auth(UINT suite)
{
    const NX_SECURE_TLS_CIPHERSUITE_INFO *table =
        ami_crypto_tls_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table;
    USHORT n = ami_crypto_tls_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table_size;
    USHORT i;

    for (i = 0; i < n; i++)
        if (table[i].nx_secure_tls_ciphersuite == suite)
            return table[i].nx_secure_tls_public_auth;
    return NX_NULL;
}

static int server_load(Server *s)
{
    memset(s, 0, sizeof(*s));
    s->der = (UCHAR *)malloc(test_device_cert_der_len);
    s->key = (UCHAR *)malloc(test_device_cert_key_der_len);
    if (s->der == NULL || s->key == NULL)
        return 0;
    memcpy(s->der, test_device_cert_der, test_device_cert_der_len);
    memcpy(s->key, test_device_cert_key_der, test_device_cert_key_der_len);
    return _nx_secure_x509_certificate_initialize(
               &s->cert, s->der, (USHORT)test_device_cert_der_len, NX_NULL, 0,
               s->key, (USHORT)test_device_cert_key_der_len,
               NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER) == NX_SUCCESS;
}

static void server_free(Server *s)
{
    memset(s->der, 0x5A, test_device_cert_der_len);
    memset(s->key, 0x5A, test_device_cert_key_der_len);
    free(s->der);
    free(s->key);
    s->der = s->key = NULL;
}

static ULONG crt_ops(void)
{
    AMI_TLS_CRYPTO_COUNTERS a, b;

    ami_tls_crypto_counters_get(&a, &b);
    return a.ami_rsa_private_crt_count + b.ami_rsa_private_crt_count;
}

static ULONG plain_ops(void)
{
    AMI_TLS_CRYPTO_COUNTERS a, b;

    ami_tls_crypto_counters_get(&a, &b);
    return a.ami_rsa_private_plain_count + b.ami_rsa_private_plain_count;
}

/* A server's private-key operation, as nx_secure makes it: the modulus is the
   certificate's public-key modulus, the key the private exponent. */
static UINT sign(Server *s, UCHAR out[SIG_BYTES])
{
    const NX_SECURE_RSA_PUBLIC_KEY  *pub  = &s->cert.nx_secure_x509_public_key.rsa_public_key;
    const NX_SECURE_RSA_PRIVATE_KEY *priv = &s->cert.nx_secure_x509_private_key.rsa_private_key;
    UCHAR  in[SIG_BYTES];
    VOID  *handler = NX_NULL;
    UINT   status;

    memset(in, 0x11, sizeof(in));
    in[0] = 0x00;
    in[1] = 0x01;

    status = rsa->nx_crypto_init((NX_CRYPTO_METHOD *)rsa,
                                 (UCHAR *)pub->nx_secure_rsa_public_modulus,
                                 (NX_CRYPTO_KEY_SIZE)(pub->nx_secure_rsa_public_modulus_length << 3),
                                 &handler, rsa_metadata, rsa_metadata_size);
    if (status != NX_CRYPTO_SUCCESS)
        return status;
    status = rsa->nx_crypto_operation(NX_CRYPTO_DECRYPT, handler, (NX_CRYPTO_METHOD *)rsa,
                                      (UCHAR *)priv->nx_secure_rsa_private_exponent,
                                      (NX_CRYPTO_KEY_SIZE)(priv->nx_secure_rsa_private_exponent_length << 3),
                                      in, SIG_BYTES, NX_NULL, out, SIG_BYTES,
                                      rsa_metadata, rsa_metadata_size, NX_NULL, NX_NULL);
    if (rsa->nx_crypto_cleanup)
        (void)rsa->nx_crypto_cleanup(rsa_metadata);
    return status;
}

int main(void)
{
    Server a, b, c;
    UCHAR  sig_a[SIG_BYTES], sig_b[SIG_BYTES], sig[SIG_BYTES];
    ULONG  crt, plain;

    rsa = suite_auth(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
    CHECK(rsa != NX_NULL);
    if (rsa == NX_NULL)
        return 1;
    rsa_metadata_size = rsa->nx_crypto_metadata_area_size;
    rsa_metadata = (UCHAR *)malloc(rsa_metadata_size);
    CHECK(rsa_metadata != NULL);

    CHECK(server_load(&a));
    CHECK(server_load(&b));
    CHECK(ami_tls_rsa_key_register(&a.cert) == NX_SUCCESS);
    CHECK(ami_tls_rsa_key_register(&b.cert) == NX_SUCCESS);
    CHECK(ami_tls_rsa_key_register(&b.cert) == NX_SUCCESS);    /* no second slot */

    crt = crt_ops();
    CHECK(sign(&a, sig_a) == NX_CRYPTO_SUCCESS);
    CHECK(sign(&b, sig_b) == NX_CRYPTO_SUCCESS);
    CHECK(crt_ops() == crt + 2);
    CHECK(memcmp(sig_a, sig_b, SIG_BYTES) == 0);

    /* A closes: its entry goes, its buffers are overwritten and freed. */
    ami_tls_rsa_key_forget(&a.cert);
    server_free(&a);
    crt = crt_ops();
    CHECK(sign(&b, sig) == NX_CRYPTO_SUCCESS);
    CHECK(crt_ops() == crt + 1);
    CHECK(memcmp(sig, sig_b, SIG_BYTES) == 0);

    /* The same modulus bytes, never registered: no primes borrowed from B. */
    CHECK(server_load(&c));
    crt = crt_ops();
    plain = plain_ops();
    CHECK(sign(&c, sig) == NX_CRYPTO_SUCCESS);
    CHECK(crt_ops() == crt);
    CHECK(plain_ops() == plain + 1);
    CHECK(memcmp(sig, sig_b, SIG_BYTES) == 0);

    /* Forgetting one never registered, or twice, touches nothing else. */
    ami_tls_rsa_key_forget(&c.cert);
    ami_tls_rsa_key_forget(&a.cert);
    crt = crt_ops();
    CHECK(sign(&b, sig) == NX_CRYPTO_SUCCESS);
    CHECK(crt_ops() == crt + 1);

    /* B closes: nothing left, the plain path. */
    ami_tls_rsa_key_forget(&b.cert);
    plain = plain_ops();
    CHECK(sign(&b, sig) == NX_CRYPTO_SUCCESS);
    CHECK(plain_ops() == plain + 1);
    CHECK(memcmp(sig, sig_b, SIG_BYTES) == 0);

    server_free(&b);
    server_free(&c);
    free(rsa_metadata);

    printf("RESULT tls_rsa_key_regression checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}
