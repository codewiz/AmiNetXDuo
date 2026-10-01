/*
 * AmiNetXDuo, crypto68k correctness gate.
 *
 * SPDX-License-Identifier: MIT
 */

#include "c68k_support.h"
#include "c68k_timer.h"
#include "aminetxduo/crashguard.h"

#include <exec/types.h>
#include <exec/execbase.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "c68k_vectors.h"
#include "c68k_chacha20.h"

static const char *const c68k_prim_names[3] =
{
    "portable C",
    "68020 assembly",
    "MULU.W assembly, multiply-accumulate only"
};


#define T_MAX_LIMBS         64u             /* RSA-2048 */
#define T_POWM_SCRATCH      4096u           /* > C68K_POWM_SCRATCH_LIMBS(64, 6) */
#define T_HN_SCRATCH        2048u
#define T_CRT_HN_SCRATCH    4096u

static c68k_limb    t_m[T_MAX_LIMBS];
static c68k_limb    t_x[T_MAX_LIMBS];
static c68k_limb    t_y[T_MAX_LIMBS];
static c68k_limb    t_exp[T_MAX_LIMBS];
static c68k_limb    t_mine[T_MAX_LIMBS * 2 + 8];
static c68k_limb    t_work[C68K_MONT_WORK_LIMBS(T_MAX_LIMBS)];
static c68k_limb    t_scratch[T_POWM_SCRATCH];
static c68k_limb    t_hn_scratch[T_HN_SCRATCH];
static c68k_limb    t_ref_result[T_MAX_LIMBS * 2 + 8];
static c68k_limb    t_tmp[T_MAX_LIMBS * 2 + 8];

static ULONG        t_failures;
static ULONG        t_checks;


static VOID t_fail(const char *what, ULONG a, ULONG b)
{

    t_failures++;
    if (t_failures <= 20u)
    {
        c68k_log("  FAIL %s (%lu, %lu)", (LONG)what, a, b);
    }
}


static VOID t_known_answers(VOID)
{

UINT    i;
UINT    status;


    c68k_log("");
    c68k_log("1. Known answers (Python arbitrary precision):");

    for (i = 0; i < (sizeof(t_kats) / sizeof(t_kats[0])); i++)
    {
        status = c68k_mont_power_modulus(t_mine,
                                         t_kats[i].x, t_kats[i].x_len,
                                         t_kats[i].e, t_kats[i].e_len,
                                         t_kats[i].m, t_kats[i].m_len,
                                         t_scratch, T_POWM_SCRATCH);
        t_checks++;
        if (status != NX_CRYPTO_SUCCESS)
        {
            t_fail("KAT status", i, status);
            continue;
        }
        if (c68k_cmp(t_mine, t_kats[i].expected, t_kats[i].m_len) != 0)
        {
            t_fail("KAT value", i, 0);
        }
    }
    c68k_log("  %lu small modexp vectors", (ULONG)i);

    status = c68k_mont_power_modulus(t_mine, t_msg, 64u, t_e, 1u, t_n, 64u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if ((status != NX_CRYPTO_SUCCESS) ||
        (c68k_cmp(t_mine, t_msg_pub, 64u) != 0))
    {
        t_fail("RSA-2048 public KAT", status, 0);
    }
    else
    {
        c68k_log("  RSA-2048 public (e=65537)  OK");
    }

    status = c68k_mont_power_modulus(t_mine, t_msg, 64u, t_d, 64u, t_n, 64u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if ((status != NX_CRYPTO_SUCCESS) ||
        (c68k_cmp(t_mine, t_msg_priv, 64u) != 0))
    {
        t_fail("RSA-2048 private KAT", status, 0);
    }
    else
    {
        c68k_log("  RSA-2048 private (d, 2048 bit)  OK");
    }
}


static c68k_limb t_addmul_model(c68k_limb *r, const c68k_limb *b, UINT n,
                                c68k_limb a)
{

UINT                i;
unsigned long long  acc = 0;


    for (i = 0; i < n; i++)
    {
        acc = (unsigned long long)r[i] +
              ((unsigned long long)a * (unsigned long long)b[i]) +
              (acc >> 32);
        r[i] = (c68k_limb)acc;
    }

    return((c68k_limb)(acc >> 32));
}

/* Bias operands towards the values where carry logic breaks. */
static c68k_limb t_extreme(VOID)
{

c68k_limb   v = c68k_rand();


    switch (v & 7u)
    {
    case 0:  return(0xFFFFFFFFUL);
    case 1:  return(0xFFFFFFFEUL);
    case 2:  return(0u);
    case 3:  return(1u);
    case 4:  return(0x80000000UL);
    default: return(c68k_rand());
    }
}

static VOID t_primitive(VOID)
{

UINT        trial;
UINT        i;
UINT        n;
c68k_limb   a;
c68k_limb   c_mine;
c68k_limb   c_model;
UINT        mismatch = 0;


    c68k_log("");
    c68k_log("2. c68k_addmul_1 against a straight-line model:");

    for (trial = 0; trial < 4000u; trial++)
    {
        n = (UINT)(c68k_rand() % 71u);          /* 0..70, including 0 and 1 */
        a = t_extreme();

        for (i = 0; i < n; i++)
        {
            t_x[i % T_MAX_LIMBS] = 0;           /* keep the arrays in range */
        }
        for (i = 0; i < n; i++)
        {
            t_y[i] = t_extreme();
            t_mine[i] = t_extreme();
            t_ref_result[i] = t_mine[i];
        }

        c_mine  = C68K_ADDMUL_1(t_mine, t_y, n, a);
        c_model = t_addmul_model(t_ref_result, t_y, n, a);

        t_checks++;
        if (c_mine != c_model)
        {
            mismatch++;
            t_fail("addmul carry", trial, n);
            continue;
        }
        for (i = 0; i < n; i++)
        {
            if (t_mine[i] != t_ref_result[i])
            {
                mismatch++;
                t_fail("addmul limb", trial, i);
                break;
            }
        }
    }

    c68k_log("  4000 trials, n = 0..70, extreme-biased operands: %lu mismatches",
             (ULONG)mismatch);
}


static VOID t_mont_differential(UINT trials)
{

UINT                    trial;
UINT                    m_len;
UINT                    i;
c68k_limb               n0inv;
NX_CRYPTO_HUGE_NUMBER   m_hn, x_hn, y_hn, r_hn;
UINT                    bad_mul = 0;
UINT                    bad_sqr = 0;


    c68k_log("");
    c68k_log("3. c68k_mont_mul / c68k_mont_sqr vs _nx_crypto_huge_number_mont:");

    for (trial = 0; trial < trials; trial++)
    {
        m_len = (UINT)(c68k_rand() % 32u) + 1u;         /* 1..32 limbs */

        c68k_rand_limbs(t_m, m_len);
        t_m[0] |= 1u;                                   /* Montgomery needs odd */

        c68k_rand_limbs(t_x, m_len);
        c68k_rand_limbs(t_y, m_len);

        /* Reduce the operands below the modulus with the vendored divider, so
           the inputs are exactly what a real Montgomery step would see. */
        c68k_hn_set(&m_hn, t_m, m_len, m_len);
        c68k_hn_set(&x_hn, t_x, m_len, T_MAX_LIMBS);
        c68k_hn_set(&y_hn, t_y, m_len, T_MAX_LIMBS);
        _nx_crypto_huge_number_modulus(&x_hn, &m_hn);
        _nx_crypto_huge_number_modulus(&y_hn, &m_hn);
        for (i = x_hn.nx_crypto_huge_number_size; i < m_len; i++)
        {
            t_x[i] = 0;
        }
        for (i = y_hn.nx_crypto_huge_number_size; i < m_len; i++)
        {
            t_y[i] = 0;
        }
        c68k_hn_set(&x_hn, t_x, m_len, T_MAX_LIMBS);
        c68k_hn_set(&y_hn, t_y, m_len, T_MAX_LIMBS);

        n0inv = c68k_mont_n0inv(t_m[0]);

        c68k_hn_set(&r_hn, t_ref_result, 0, T_MAX_LIMBS * 2);
        _nx_crypto_huge_number_mont(&m_hn, n0inv, &x_hn, &y_hn, &r_hn);
        c68k_mont_mul(t_mine, t_x, t_y, t_m, m_len, n0inv, t_work);

        t_checks++;
        if (!c68k_hn_equals(&r_hn, t_mine, m_len))
        {
            bad_mul++;
            t_fail("mont_mul", trial, m_len);
        }

        c68k_hn_set(&r_hn, t_ref_result, 0, T_MAX_LIMBS * 2);
        _nx_crypto_huge_number_mont(&m_hn, n0inv, &x_hn, &x_hn, &r_hn);
        c68k_mont_sqr(t_mine, t_x, t_m, m_len, n0inv, t_work);

        t_checks++;
        if (!c68k_hn_equals(&r_hn, t_mine, m_len))
        {
            bad_sqr++;
            t_fail("mont_sqr", trial, m_len);
        }
    }

    c68k_log("  %lu trials, m 1..32 limbs: %lu mul, %lu sqr mismatches",
             (ULONG)trials, (ULONG)bad_mul, (ULONG)bad_sqr);
}


static VOID t_powm_differential(UINT trials)
{

UINT                    trial;
UINT                    m_len;
UINT                    e_len;
UINT                    top_bits;
UINT                    i;
UINT                    status;
UINT                    bad = 0;
NX_CRYPTO_HUGE_NUMBER   m_hn, x_hn, e_hn, r_hn;


    c68k_log("");
    c68k_log("4. c68k_mont_power_modulus vs _nx_crypto_huge_number_mont_power_modulus:");

    for (trial = 0; trial < trials; trial++)
    {
        m_len = (UINT)(c68k_rand() % 12u) + 1u;         /* 1..12 limbs */
        e_len = (UINT)(c68k_rand() % 4u) + 1u;          /* 1..4 limbs  */

        c68k_rand_limbs(t_m, m_len);
        t_m[0] |= 1u;

        c68k_rand_limbs(t_x, m_len);
        c68k_rand_limbs(t_exp, e_len);

        top_bits = (UINT)(c68k_rand() % 32u) + 1u;
        t_exp[e_len - 1] &= (c68k_limb)(0xFFFFFFFFUL >> (32u - top_bits));
        if (t_exp[e_len - 1] == 0)
        {
            t_exp[e_len - 1] = 1u;
        }

        c68k_hn_set(&m_hn, t_m, m_len, m_len);
        c68k_hn_set(&x_hn, t_x, m_len, T_MAX_LIMBS);
        _nx_crypto_huge_number_modulus(&x_hn, &m_hn);
        for (i = x_hn.nx_crypto_huge_number_size; i < m_len; i++)
        {
            t_x[i] = 0;
        }

        /* Reference.  It squares into `result`, so that buffer needs 2*(m+1). */
        for (i = 0; i < m_len; i++)
        {
            t_tmp[i] = t_x[i];
        }
        c68k_hn_set(&x_hn, t_tmp, m_len, T_MAX_LIMBS);
        c68k_hn_set(&e_hn, t_exp, e_len, T_MAX_LIMBS);
        c68k_hn_set(&r_hn, t_ref_result, 0, T_MAX_LIMBS * 2);
        c68k_hn_set(&m_hn, t_m, m_len, m_len);
        _nx_crypto_huge_number_mont_power_modulus(&x_hn, &e_hn, &m_hn, &r_hn,
                                                  t_hn_scratch);

        status = c68k_mont_power_modulus(t_mine, t_x, m_len, t_exp, e_len,
                                         t_m, m_len,
                                         t_scratch, T_POWM_SCRATCH);

        t_checks++;
        if (status != NX_CRYPTO_SUCCESS)
        {
            bad++;
            t_fail("powm status", trial, status);
            continue;
        }
        if (!c68k_hn_equals(&r_hn, t_mine, m_len))
        {
            bad++;
            t_fail("powm value", trial, (m_len << 8) | e_len);
        }
    }

    c68k_log("  %lu trials, m 1..12 limbs, e 1..4 limbs, top limb 1..32 bits: %lu mismatches",
             (ULONG)trials, (ULONG)bad);
}


static VOID t_edge_cases(VOID)
{

UINT                    status;
UINT                    i;
c68k_limb               zero_e[1];
NX_CRYPTO_HUGE_NUMBER   m_hn, x_hn, e_hn, r_hn;


    c68k_log("");
    c68k_log("5. Edge cases:");

    t_m[0] = 0xFFFFFFFFUL;
    t_x[0] = 0;
    zero_e[0] = 5u;
    status = c68k_mont_power_modulus(t_mine, t_x, 1u, zero_e, 1u, t_m, 1u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if ((status != NX_CRYPTO_SUCCESS) || (t_mine[0] != 0u))
    {
        t_fail("0^5 mod (2^32-1)", status, t_mine[0]);
    }

    /* The zero-exponent identity still has to be reduced.  Modulo one, the
       only residue is zero rather than the literal one. */
    t_m[0] = 1u;
    t_x[0] = 0xDEADBEEFu;
    zero_e[0] = 0u;
    status = c68k_mont_power_modulus(t_mine, t_x, 1u, zero_e, 1u, t_m, 1u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if ((status != NX_CRYPTO_SUCCESS) || (t_mine[0] != 0u))
    {
        t_fail("x^0 mod 1", status, t_mine[0]);
    }

    /* e = 0 -> 1, checked against the vendored routine, which also has to
       cope with an exponent whose only limb is zero. */
    c68k_rand_limbs(t_m, 8u);
    t_m[0] |= 1u;
    c68k_rand_limbs(t_x, 8u);
    zero_e[0] = 0u;

    c68k_hn_set(&m_hn, t_m, 8u, 8u);
    c68k_hn_set(&x_hn, t_x, 8u, T_MAX_LIMBS);
    _nx_crypto_huge_number_modulus(&x_hn, &m_hn);
    for (i = x_hn.nx_crypto_huge_number_size; i < 8u; i++)
    {
        t_x[i] = 0;
    }

    for (i = 0; i < 8u; i++)
    {
        t_tmp[i] = t_x[i];
    }
    c68k_hn_set(&x_hn, t_tmp, 8u, T_MAX_LIMBS);
    c68k_hn_set(&e_hn, zero_e, 1u, 1u);
    c68k_hn_set(&r_hn, t_ref_result, 0, T_MAX_LIMBS * 2);
    c68k_hn_set(&m_hn, t_m, 8u, 8u);
    _nx_crypto_huge_number_mont_power_modulus(&x_hn, &e_hn, &m_hn, &r_hn,
                                              t_hn_scratch);

    status = c68k_mont_power_modulus(t_mine, t_x, 8u, zero_e, 1u, t_m, 8u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if ((status != NX_CRYPTO_SUCCESS) || !c68k_hn_equals(&r_hn, t_mine, 8u))
    {
        t_fail("x^0", status, 0);
    }

    /* An even modulus must be refused, not silently answered wrongly. */
    t_m[0] &= ~1u;
    status = c68k_mont_power_modulus(t_mine, t_x, 8u, t_exp, 1u, t_m, 8u,
                                     t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if (status == NX_CRYPTO_SUCCESS)
    {
        t_fail("even modulus accepted", 0, 0);
    }

    /* Too little scratch must be refused too. */
    t_m[0] |= 1u;
    status = c68k_mont_power_modulus(t_mine, t_x, 8u, t_exp, 1u, t_m, 8u,
                                     t_scratch, 4u);
    t_checks++;
    if (status == NX_CRYPTO_SUCCESS)
    {
        t_fail("undersized scratch accepted", 0, 0);
    }

    c68k_log("  0^e, x^0, x^0 mod 1, even modulus, undersized scratch");
}


/* RSA-2048 private with CRT: what a TLS server with an RSA key runs, and
   nothing else here reaches.  The two modular inverses it opens with are a
   binary GCD that ends only when u reaches zero, so a wrong carry there
   hangs rather than fails. */
static c68k_limb    t_crt_x[T_MAX_LIMBS];
static c68k_limb    t_crt_e[T_MAX_LIMBS];
static c68k_limb    t_crt_m[T_MAX_LIMBS];
static c68k_limb    t_crt_p[T_MAX_LIMBS / 2];
static c68k_limb    t_crt_q[T_MAX_LIMBS / 2];
static c68k_limb    t_crt_inv[T_MAX_LIMBS + 8];
static c68k_limb    t_crt_prod[T_MAX_LIMBS * 2 + 8];
static c68k_limb    t_crt_hn_scratch[T_CRT_HN_SCRATCH];

static VOID t_crt(VOID)
{

UINT                    i;
NX_CRYPTO_HUGE_NUMBER   x_hn, e_hn, m_hn, p_hn, q_hn, inv_hn, prod_hn, r_hn;


    c68k_log("");
    c68k_log("6. RSA-2048 private, CRT:");

    for (i = 0; i < 32u; i++)
    {
        t_crt_p[i] = t_p[i];
        t_crt_q[i] = t_q[i];
    }

    /* q^-1 mod p on its own, checked by multiplying back. */
    c68k_hn_set(&p_hn, t_crt_p, 32u, 32u);
    c68k_hn_set(&q_hn, t_crt_q, 32u, 32u);
    c68k_hn_set(&inv_hn, t_crt_inv, 0, T_MAX_LIMBS + 8);
    _nx_crypto_huge_number_inverse_modulus_prime(&q_hn, &p_hn, &inv_hn,
                                                 t_crt_hn_scratch);
    c68k_hn_set(&prod_hn, t_crt_prod, 0, T_MAX_LIMBS * 2 + 8);
    _nx_crypto_huge_number_multiply(&inv_hn, &q_hn, &prod_hn);
    _nx_crypto_huge_number_modulus(&prod_hn, &p_hn);
    t_checks++;
    if ((prod_hn.nx_crypto_huge_number_size != 1u) ||
        (prod_hn.nx_crypto_huge_number_data[0] != 1u) ||
        prod_hn.nx_crypto_huge_number_is_negative)
    {
        t_fail("q^-1 mod p", prod_hn.nx_crypto_huge_number_size,
               prod_hn.nx_crypto_huge_number_data[0]);
    }
    else
    {
        c68k_log("  q^-1 mod p  OK");
    }

    for (i = 0; i < 64u; i++)
    {
        t_crt_x[i] = t_msg[i];
        t_crt_e[i] = t_d[i];
        t_crt_m[i] = t_n[i];
    }
    c68k_hn_set(&x_hn, t_crt_x, 64u, T_MAX_LIMBS);
    c68k_hn_set(&e_hn, t_crt_e, 64u, T_MAX_LIMBS);
    c68k_hn_set(&m_hn, t_crt_m, 64u, 64u);
    c68k_hn_set(&p_hn, t_crt_p, 32u, 32u);
    c68k_hn_set(&q_hn, t_crt_q, 32u, 32u);
    c68k_hn_set(&r_hn, t_ref_result, 0, T_MAX_LIMBS * 2 + 8);
    c68k_crt_power_modulus(&x_hn, &e_hn, &p_hn, &q_hn, &m_hn, &r_hn,
                           t_crt_hn_scratch, t_scratch, T_POWM_SCRATCH);
    t_checks++;
    if (!c68k_hn_equals(&r_hn, t_msg_priv, 64u))
    {
        t_fail("RSA-2048 private CRT KAT", r_hn.nx_crypto_huge_number_size, 0);
    }
    else
    {
        c68k_log("  c68k_crt_power_modulus  OK");
    }
}


/* Poly1305 and the ChaCha20-Poly1305 AEAD, RFC 8439 2.5.2 and 2.8.2, through
   the entry points the TLS record path calls.  In an AMINETXDUO_CPU=any build
   those reach the block function through c68k_vec_poly1305_blocks, a vector
   whose declaration once lacked the stack pin its two targets need, and a
   TLS 1.2 ChaCha20-Poly1305 server hung.  Only crypto68k_bulk checked these
   vectors, and it is not built for the 68000 or `any'. */
static const UCHAR t_poly_key[32] =
{
    0x85, 0xD6, 0xBE, 0x78, 0x57, 0x55, 0x6D, 0x33,
    0x7F, 0x44, 0x52, 0xFE, 0x42, 0xD5, 0x06, 0xA8,
    0x01, 0x03, 0x80, 0x8A, 0xFB, 0x0D, 0xB2, 0xFD,
    0x4A, 0xBF, 0xF6, 0xAF, 0x41, 0x49, 0xF5, 0x1B
};

static const UCHAR t_poly_tag[16] =
{
    0xA8, 0x06, 0x1D, 0xC1, 0x30, 0x51, 0x36, 0xC6,
    0xC2, 0x2B, 0x8B, 0xAF, 0x0C, 0x01, 0x27, 0xA9
};

static const UCHAR t_aead_key[32] =
{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
};

static const UCHAR t_aead_nonce[12] =
{
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};

static const UCHAR t_aead_aad[12] =
{
    0x50, 0x51, 0x52, 0x53, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7
};

static const UCHAR t_aead_tag[16] =
{
    0x1A, 0xE1, 0x0B, 0x59, 0x4F, 0x09, 0xE2, 0x6A,
    0x7E, 0x90, 0x2E, 0xCB, 0xD0, 0x60, 0x06, 0x91
};

static const UCHAR t_aead_plain[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only "
    "one tip for the future, sunscreen would be it.";

static C68K_POLY1305            t_poly;
static C68K_CHACHA20_POLY1305   t_aead;
static UCHAR                    t_aead_buf[128];

static VOID t_bytes(const char *what, const UCHAR *got, const UCHAR *want,
                    ULONG n)
{

ULONG   i;


    t_checks++;
    for (i = 0; i < n; i++)
    {
        if (got[i] != want[i])
        {
            t_fail(what, i, got[i]);
            return;
        }
    }
}

static VOID t_poly1305(VOID)
{

UCHAR   tag[16];


    c68k_log("");
    c68k_log("7. Poly1305 and ChaCha20-Poly1305 (RFC 8439), %s blocks:",
             (LONG)(c68k_poly1305_blocks_is_asm() ? "assembly" : "portable C"));

    c68k_poly1305_initialize(&t_poly, t_poly_key);
    c68k_poly1305_update(&t_poly,
                         (const UCHAR *)"Cryptographic Forum Research Group",
                         34uL);
    c68k_poly1305_finish(&t_poly, tag);
    t_bytes("RFC 8439 2.5.2 tag", tag, t_poly_tag, 16uL);

    c68k_chacha20_poly1305_initialize(&t_aead, t_aead_key, t_aead_nonce);
    c68k_chacha20_poly1305_associate(&t_aead, t_aead_aad, 12uL);
    c68k_chacha20_poly1305_encrypt(&t_aead, t_aead_plain, t_aead_buf, 114uL);
    c68k_chacha20_poly1305_tag(&t_aead, tag);
    t_bytes("RFC 8439 2.8.2 AEAD tag", tag, t_aead_tag, 16uL);

    c68k_chacha20_poly1305_initialize(&t_aead, t_aead_key, t_aead_nonce);
    c68k_chacha20_poly1305_associate(&t_aead, t_aead_aad, 12uL);
    c68k_chacha20_poly1305_decrypt(&t_aead, t_aead_buf, t_aead_buf, 114uL);
    c68k_chacha20_poly1305_tag(&t_aead, tag);
    t_bytes("RFC 8439 2.8.2 plaintext", t_aead_buf, t_aead_plain, 114uL);
    t_bytes("RFC 8439 2.8.2 tag on decrypt", tag, t_aead_tag, 16uL);

    c68k_log("  2.5.2 tag, 2.8.2 AEAD seal and open");
}


int main(VOID)
{

ULONG           start;
CONST_STRPTR    cmdline = (CONST_STRPTR)GetArgStr();
BOOL            quick   = (cmdline != NULL) &&
                          (strchr((const char *)cmdline, 'q') != NULL);


    /* What a shipped library does at init, so this measures and checks
       what shipped: in an AMINETXDUO_CPU=any build the primitives are
       chosen here and nowhere else (src/crypto68k/c68k_cpu.c). */
    c68k_cpu_select((ULONG)SysBase->AttnFlags);

    ami_crash_set_reference((APTR)main, "crypto68k_test");
    if (!ami_crash_install())
    {
        c68k_log("CRASHED, see the serial log and DH0:crash.txt");
        c68k_flush();
        ami_crash_remove();
        return(20);
    }

    c68k_log("AmiNetXDuo, crypto68k correctness gate");
    c68k_log("  limb primitives: %s",
             (LONG)c68k_prim_names[c68k_using_assembly() % 3u]);
    if (quick)
    {
        c68k_log("  quick: no RSA-2048 known answers, differentials scaled down");
    }

    (VOID) c68k_timer_open();
    start = c68k_eclock();

    c68k_rng_seed(0x5A17C0DEUL);

    if (!quick)
    {
        t_known_answers();
    }
    t_primitive();
    t_mont_differential(quick ?  40u : 400u);
    t_powm_differential(quick ?  10u : 150u);
    t_edge_cases();
    t_crt();
    t_poly1305();

    c68k_log("");
    c68k_log("Wall time: %lu ms", c68k_eclock_millis(c68k_eclock() - start));

    if (t_failures == 0)
    {
        c68k_log("%lu checks, 0 failures, PASS", t_checks);
    }
    else
    {
        c68k_log("%lu checks, %lu failures, FAIL", t_checks, t_failures);
    }

    c68k_timer_close();
    c68k_flush();
    ami_crash_remove();

    return((t_failures == 0) ? 0 : 20);
}
