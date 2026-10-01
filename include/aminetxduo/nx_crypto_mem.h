/*
 * nx_crypto's memcpy and memset, called with the stack convention.
 *
 * nx_crypto.h calls them through volatile function pointers so that a key
 * clear on a buffer about to die is not a dead store the compiler may drop
 * (NX_SECURE_KEY_CLEAR).  Those pointers carry no calling convention, and
 * libc's memcpy and memset are __stdargs: under -mregparm every call passed
 * its arguments in d0/d1/a0 while the callee read 4..12(sp), and httpd's
 * WebSocket upgrade crashed inside memcpy.  These keep the call opaque and
 * pin it.  Included by both ways into nx_crypto.h: nx_user.h, and
 * src/tools/nx_crypto_port.h for the standalone build.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef AMINETXDUO_NX_CRYPTO_MEM_H
#define AMINETXDUO_NX_CRYPTO_MEM_H

#include <string.h>
#include <aminetxduo/asm_abi.h>

static inline void *ami_nx_crypto_memcpy(void *dest, const void *src,
                                         size_t size)
{
    AMIGA_ASM_ARGS void *(*volatile fn)(void *, const void *, size_t) = memcpy;

    return fn(dest, src, size);
}

static inline void *ami_nx_crypto_memset(void *dest, int value, size_t size)
{
    AMIGA_ASM_ARGS void *(*volatile fn)(void *, int, size_t) = memset;

    return fn(dest, value, size);
}

#define NX_CRYPTO_MEMCPY    ami_nx_crypto_memcpy
#define NX_CRYPTO_MEMSET    ami_nx_crypto_memset

#endif /* AMINETXDUO_NX_CRYPTO_MEM_H */
