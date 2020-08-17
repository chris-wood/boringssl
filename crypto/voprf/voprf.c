/* Copyright (c) 2019, Google Inc.
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

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/voprf.h>
#include <openssl/hmac.h>

#include "../ec_extra/internal.h"
#include "internal.h"

// Check argument `x` and return `r` if it is zero (NULL)
#define VOPRF_CHECK_ARG_RETURN(x, r) \
    if (!(x)) { \
        return (r); \
    }

static const uint8_t kDefaultAdditionalData[32] = {0};
static const char kFinalizeDST[18] = "oprf_derive_output";

int
oprf_generate_random_scalar(const EC_GROUP *group, EC_SCALAR *k)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(k, 0);

    int result = ec_random_nonzero_scalar(group, k, kDefaultAdditionalData);
    ec_scalar_from_montgomery(group, k, k);
    return result;
}

int
oprf_generate_random_point(const EC_GROUP *group, EC_RAW_POINT *out)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);

    EC_RAW_POINT temp;
    OPENSSL_memcpy(&temp, out, sizeof(temp));

    EC_SCALAR scalar;
    int result = oprf_blind_point(group, out, &temp, &scalar);
    OPENSSL_memset(&scalar, 0, sizeof(scalar));

    return result;
}

int
oprf_blind(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len, EC_SCALAR *r)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(M, 0);
    VOPRF_CHECK_ARG_RETURN(x, 0);
    VOPRF_CHECK_ARG_RETURN(r, 0);

    EC_POINT *X = EC_POINT_new(group);
    if (!oprf_message_to_point(group, &X->raw, x, x_len)) {
        return 0;
    }

    if (!oprf_blind_point(group, M, &X->raw, r)) {
        return 0;
    }

    return 1;
}

int
oprf_message_to_point(const EC_GROUP *group, EC_RAW_POINT *M, const uint8_t *x, size_t x_len)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(M, 0);
    VOPRF_CHECK_ARG_RETURN(x, 0);

    static const uint8_t kDST[] = "RFCXXXX-VOPRF-P384_XMD:SHA-512_SSWU_RO_";
    return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(group, M, kDST, sizeof(kDST) - 1, x, x_len);
}

int
oprf_blind_point(const EC_GROUP *group, EC_RAW_POINT *M, EC_RAW_POINT *x, EC_SCALAR *r)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(M, 0);
    VOPRF_CHECK_ARG_RETURN(x, 0);
    VOPRF_CHECK_ARG_RETURN(r, 0);

    // This samples r in Montgomery form
    if (!ec_random_nonzero_scalar(group, r, kDefaultAdditionalData)) {
        return 0;
    }
    ec_scalar_from_montgomery(group, r, r);

    return ec_point_mul_scalar(group, M, x, r);
}

int
oprf_unblind_point(const EC_GROUP *group, EC_RAW_POINT *x, EC_RAW_POINT *M, EC_SCALAR *r)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(x, 0);
    VOPRF_CHECK_ARG_RETURN(M, 0);
    VOPRF_CHECK_ARG_RETURN(r, 0);

    EC_SCALAR rinv;
    ec_scalar_to_montgomery(group, &rinv, r);
    ec_scalar_inv0_montgomery(group, &rinv, &rinv);
    ec_scalar_from_montgomery(group, &rinv, &rinv);
    return ec_point_mul_scalar(group, x, M, &rinv);
}

int
oprf_sign_point(const EC_GROUP *group, EC_RAW_POINT *N, EC_RAW_POINT *M, EC_SCALAR *k)
{
    VOPRF_CHECK_ARG_RETURN(group, 0);
    VOPRF_CHECK_ARG_RETURN(N, 0);
    VOPRF_CHECK_ARG_RETURN(M, 0);
    VOPRF_CHECK_ARG_RETURN(k, 0);

    return ec_point_mul_scalar(group, N, M, k);
}

static int point_to_cbb(CBB *out, const EC_GROUP *group,
                        const EC_AFFINE *point) {
  size_t len =
      ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0);
  if (len == 0) {
    return 0;
  }
  uint8_t *p;
  return CBB_add_space(out, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p,
                           len) == len;
}

int
oprf_finalize(const EC_GROUP *group, uint8_t output[EVP_MAX_MD_SIZE], size_t *output_len,
    const uint8_t *x, size_t x_len, EC_RAW_POINT *y)
{
    EC_AFFINE y_affine;
    if (!ec_jacobian_to_affine(group, &y_affine, y)) {
        return 0;
    }

    // struct {
    //   opaque dst<0..2^16-1>;
    //   opaque input<0..2^16-1>;
    //   opaque point<0..2^16-1>;
    // } FinalizeInput;
    CBB cbb, dst_inner, input_inner, point_inner;
    if (!CBB_init(&cbb, 0) ||
        !CBB_add_u16_length_prefixed(&cbb, &dst_inner) ||
        !CBB_add_bytes(&dst_inner, (const uint8_t *)kFinalizeDST, sizeof(kFinalizeDST)) ||
        !CBB_add_u16_length_prefixed(&cbb, &input_inner) ||
        !CBB_add_bytes(&input_inner, x, x_len) ||
        !CBB_add_u16_length_prefixed(&cbb, &point_inner) ||
        !point_to_cbb(&point_inner, group, &y_affine) ||
        !CBB_flush(&cbb)) {
      return 0;
    }

    SHA512(CBB_data(&cbb), CBB_len(&cbb), output);
    *output_len = SHA512_DIGEST_LENGTH;

    return 1;
}


int OPRF_CTX_generate_random_key(OPRF_CTX *ctx, OPRF_KEY *)
{
    return 1;
}

int OPRF_CTX_generate_random_element(OPRF_CTX *ctx, OPRF_ELEMENT *)
{
    return 1;
}

int OPRF_CTX_blind(OPRF_CTX *ctx, OPRF_ELEMENT *, const uint8_t *, size_t, OPRF_KEY *)
{
    return 1;
}

int OPRF_CTX_unblind(OPRF_CTX *ctx, OPRF_ELEMENT *, OPRF_ELEMENT *, OPRF_KEY *)
{
    return 1;
}

int OPRF_CTX_evaluate(OPRF_CTX *ctx, OPRF_ELEMENT *, OPRF_KEY *, OPRF_ELEMENT *)
{
    return 1;
}

int OPRF_CTX_finalize(OPRF_CTX *ctx, const uint8_t *, size_t, OPRF_ELEMENT *, const uint8_t *, size_t)
{
    return 1;
}
