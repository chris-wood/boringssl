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

#ifndef OPENSSL_HEADER_VOPRF_INTERNAL_H
#define OPENSSL_HEADER_VOPRF_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>
#include <openssl/evp.h>

#include "../fipsmodule/ec/internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

int
voprf_generate_random_scalar(const EC_GROUP *group, EC_SCALAR *k);

int
voprf_generate_random_point(const EC_GROUP *group, EC_RAW_POINT *out);

int
voprf_blind(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len, EC_SCALAR *r);

int
voprf_message_to_point(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len);

int
voprf_blind_point(const EC_GROUP *group, EC_RAW_POINT *M, EC_RAW_POINT *x, EC_SCALAR *r);

int
voprf_unblind_point(const EC_GROUP *group, EC_RAW_POINT *x, EC_RAW_POINT *M, EC_SCALAR *r);

int
voprf_sign_point(const EC_GROUP *group, EC_RAW_POINT *N, EC_RAW_POINT *M, EC_SCALAR *k);

int
voprf_finalize(const EC_GROUP *group, uint8_t output[EVP_MAX_MD_SIZE],
    size_t *output_len, const uint8_t *x, size_t x_len, EC_RAW_POINT *y);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
