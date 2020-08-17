/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_OPRF_INTERNAL_H
#define OPENSSL_HEADER_OPRF_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>
#include <openssl/evp.h>

#include "../fipsmodule/ec/internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
    EC_SCALAR key;
} OPRF_KEY;

typedef struct {
    EC_RAW_POINT point;
} OPRF_ELEMENT;

typedef struct oprf_ctx_st {
    const EC_GROUP *group; // Group
    const EVP_MD *digest;  // Random oracle
} OPRF_CTX;

OPENSSL_EXPORT void OPRF_CTX_init(OPRF_CTX *ctx);
OPENSSL_EXPORT void OPRF_CTX_cleanup(OPRF_CTX *ctx);

// struct oprf_method_st {
//     int (*generate_random_key)(OPRF_CTX *, OPRF_KEY *);
//     int (*generate_random_element)(OPRF_CTX *, OPRF_ELEMENT *);
//     int (*blind)(OPRF_CTX *, OPRF_ELEMENT *, const uint8_t *, size_t, OPRF_KEY *);
//     int (*unblind)(OPRF_CTX *, OPRF_ELEMENT *, OPRF_ELEMENT *, OPRF_KEY *);
//     int (*evaluate)(OPRF_CTX *, OPRF_ELEMENT *, OPRF_KEY *, OPRF_ELEMENT *);
//     int (*finalize)(OPRF_CTX *, const uint8_t *, size_t, OPRF_ELEMENT *, const uint8_t *, size_t);
// };

int OPRF_CTX_generate_random_key(OPRF_CTX *ctx, OPRF_KEY *);
int OPRF_CTX_generate_random_element(OPRF_CTX *ctx, OPRF_ELEMENT *);
int OPRF_CTX_blind(OPRF_CTX *ctx, OPRF_ELEMENT *, const uint8_t *, size_t, OPRF_KEY *);
int OPRF_CTX_unblind(OPRF_CTX *ctx, OPRF_ELEMENT *, OPRF_ELEMENT *, OPRF_KEY *);
int OPRF_CTX_evaluate(OPRF_CTX *ctx, OPRF_ELEMENT *, OPRF_KEY *, OPRF_ELEMENT *);
int OPRF_CTX_finalize(OPRF_CTX *ctx, const uint8_t *, size_t, OPRF_ELEMENT *, const uint8_t *, size_t);

int
oprf_generate_random_scalar(const EC_GROUP *group, EC_SCALAR *k);

int
oprf_generate_random_point(const EC_GROUP *group, EC_RAW_POINT *out);

int
oprf_blind(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len, EC_SCALAR *r);

int
oprf_message_to_point(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len);

int
oprf_blind_point(const EC_GROUP *group, EC_RAW_POINT *M, EC_RAW_POINT *x, EC_SCALAR *r);

int
oprf_unblind_point(const EC_GROUP *group, EC_RAW_POINT *x, EC_RAW_POINT *M, EC_SCALAR *r);

int
oprf_sign_point(const EC_GROUP *group, EC_RAW_POINT *N, EC_RAW_POINT *M, EC_SCALAR *k);

int
oprf_finalize(const EC_GROUP *group, uint8_t output[EVP_MAX_MD_SIZE],
    size_t *output_len, const uint8_t *x, size_t x_len, EC_RAW_POINT *y);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_OPRF_INTERNAL_H
