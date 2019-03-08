// Copyright (c) 2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <stdint.h>

#if defined(HAVE_ENDIAN_H)
#include <endian.h>
#endif

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
#if HAVE_DECL_LE32TOH == 1
    return le32toh(*((uint32_t*)ptr));
#elif !defined(WORDS_BIGENDIAN)
    return *((uint32_t*)ptr);
#else
    return ((uint32_t)ptr[3] << 24 | (uint32_t)ptr[2] << 16 | (uint32_t)ptr[1] << 8 | (uint32_t)ptr[0]);
#endif
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
#if HAVE_DECL_LE64TOH == 1
    return le64toh(*((uint64_t*)ptr));
#elif !defined(WORDS_BIGENDIAN)
    return *((uint64_t*)ptr);
#else
    return ((uint64_t)ptr[7] << 56 | (uint64_t)ptr[6] << 48 | (uint64_t)ptr[5] << 40 | (uint64_t)ptr[4] << 32 |
            (uint64_t)ptr[3] << 24 | (uint64_t)ptr[2] << 16 | (uint64_t)ptr[1] << 8 | (uint64_t)ptr[0]);
#endif
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
#if HAVE_DECL_HTOLE32 == 1
    *((uint32_t*)ptr) = htole32(x);
#elif !defined(WORDS_BIGENDIAN)
    *((uint32_t*)ptr) = x;
#else
    ptr[3] = x >> 24;
    ptr[2] = x >> 16;
    ptr[1] = x >> 8;
    ptr[0] = x;
#endif
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
#if HAVE_DECL_HTOLE64 == 1
    *((uint64_t*)ptr) = htole64(x);
#elif !defined(WORDS_BIGENDIAN)
    *((uint64_t*)ptr) = x;
#else
    ptr[7] = x >> 56;
    ptr[6] = x >> 48;
    ptr[5] = x >> 40;
    ptr[4] = x >> 32;
    ptr[3] = x >> 24;
    ptr[2] = x >> 16;
    ptr[1] = x >> 8;
    ptr[0] = x;
#endif
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
#if HAVE_DECL_BE32TOH == 1
    return be32toh(*((uint32_t*)ptr));
#else
    return ((uint32_t)ptr[0] << 24 | (uint32_t)ptr[1] << 16 | (uint32_t)ptr[2] << 8 | (uint32_t)ptr[3]);
#endif
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
#if HAVE_DECL_BE64TOH == 1
    return be64toh(*((uint64_t*)ptr));
#else
    return ((uint64_t)ptr[0] << 56 | (uint64_t)ptr[1] << 48 | (uint64_t)ptr[2] << 40 | (uint64_t)ptr[3] << 32 |
            (uint64_t)ptr[4] << 24 | (uint64_t)ptr[5] << 16 | (uint64_t)ptr[6] << 8 | (uint64_t)ptr[7]);
#endif
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
#if HAVE_DECL_HTOBE32 == 1
    *((uint32_t*)ptr) = htobe32(x);
#else
    ptr[0] = x >> 24;
    ptr[1] = x >> 16;
    ptr[2] = x >> 8;
    ptr[3] = x;
#endif
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
#if HAVE_DECL_HTOBE64 == 1
    *((uint64_t*)ptr) = htobe64(x);
#else
    ptr[0] = x >> 56;
    ptr[1] = x >> 48;
    ptr[2] = x >> 40;
    ptr[3] = x >> 32;
    ptr[4] = x >> 24;
    ptr[5] = x >> 16;
    ptr[6] = x >> 8;
    ptr[7] = x;
#endif
}


#pragma once

/* From fe.h */

typedef int32_t fe[10];

/* From ge.h */

typedef struct {
    fe X;
    fe Y;
    fe Z;
} ge_p2;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1;

typedef struct {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp;

typedef struct {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached;

/* From ge_add.c */

void ge_add(ge_p1p1 *, const ge_p3 *, const ge_cached *);

/* From ge_double_scalarmult.c, modified */

typedef ge_cached ge_dsmp[8];
extern const ge_precomp ge_Bi[8];
void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s);
void ge_double_scalarmult_base_vartime(ge_p2 *, const unsigned char *, const ge_p3 *, const unsigned char *);
void ge_double_scalarmult_base_vartime_p3(ge_p3 *, const unsigned char *, const ge_p3 *, const unsigned char *);

/* From ge_frombytes.c, modified */

extern const fe fe_sqrtm1;
extern const fe fe_d;
int ge_frombytes_vartime(ge_p3 *, const unsigned char *);

/* From ge_p1p1_to_p2.c */

void ge_p1p1_to_p2(ge_p2 *, const ge_p1p1 *);

/* From ge_p1p1_to_p3.c */

void ge_p1p1_to_p3(ge_p3 *, const ge_p1p1 *);

/* From ge_p2_dbl.c */

void ge_p2_dbl(ge_p1p1 *, const ge_p2 *);

/* From ge_p3_to_cached.c */

extern const fe fe_d2;
void ge_p3_to_cached(ge_cached *, const ge_p3 *);

/* From ge_p3_to_p2.c */

void ge_p3_to_p2(ge_p2 *, const ge_p3 *);

/* From ge_p3_tobytes.c */

void ge_p3_tobytes(unsigned char *, const ge_p3 *);

/* From ge_scalarmult_base.c */

extern const ge_precomp ge_base[32][8];
void ge_scalarmult_base(ge_p3 *, const unsigned char *);

/* From ge_tobytes.c */

void ge_tobytes(unsigned char *, const ge_p2 *);

/* From sc_reduce.c */

void sc_reduce(unsigned char *);

/* New code */

void ge_scalarmult(ge_p2 *, const unsigned char *, const ge_p3 *);
void ge_scalarmult_p3(ge_p3 *, const unsigned char *, const ge_p3 *);
void ge_double_scalarmult_precomp_vartime(ge_p2 *, const unsigned char *, const ge_p3 *, const unsigned char *, const ge_dsmp);
void ge_double_scalarmult_precomp_vartime2(ge_p2 *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);
void ge_double_scalarmult_precomp_vartime2_p3(ge_p3 *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);
void ge_mul8(ge_p1p1 *, const ge_p2 *);
extern const fe fe_ma2;
extern const fe fe_ma;
extern const fe fe_fffb1;
extern const fe fe_fffb2;
extern const fe fe_fffb3;
extern const fe fe_fffb4;
extern const ge_p3 ge_p3_identity;
extern const ge_p3 ge_p3_H;
void ge_fromfe_frombytes_vartime(ge_p2 *, const unsigned char *);
void sc_0(unsigned char *);
void sc_reduce32(unsigned char *);
void sc_add(unsigned char *, const unsigned char *, const unsigned char *);
void sc_sub(unsigned char *, const unsigned char *, const unsigned char *);
void sc_mulsub(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *);
void sc_mul(unsigned char *, const unsigned char *, const unsigned char *);
void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);
int sc_check(const unsigned char *);
int sc_isnonzero(const unsigned char *); /* Doesn't normalize */

// internal
uint64_t load_3(const unsigned char *in);
uint64_t load_4(const unsigned char *in);
void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void fe_add(fe h, const fe f, const fe g);
void fe_tobytes(unsigned char *, const fe);
void fe_invert(fe out, const fe z);

int ge_p3_is_point_at_infinity(const ge_p3 *p);

#endif // BITCOIN_CRYPTO_COMMON_H
