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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>

#include "../ec_extra/internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../internal.h"
#include "../test/test_util.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

namespace {

TEST(VOPRFTest, RandomPoint) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  bssl::UniquePtr<EC_POINT> P(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> Q(EC_POINT_new(group));
  ASSERT_EQ(voprf_generate_random_point(group, &P->raw), 1);
}

TEST(VOPRFTest, BlindUnlind) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  bssl::UniquePtr<EC_POINT> B(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> P(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> Q(EC_POINT_new(group));
  ASSERT_EQ(voprf_generate_random_point(group, &B->raw), 1);

  EC_SCALAR r;
  ASSERT_EQ(voprf_blind_point(group, &P->raw, &B->raw, &r), 1);
  ASSERT_EQ(voprf_unblind_point(group, &Q->raw, &P->raw, &r), 1);
  EXPECT_EQ(0, EC_POINT_cmp(group, B.get(), Q.get(), nullptr));
}

TEST(VOPRFTest, MessageToPoint) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  const char message[] = "hello, OPRF";
  size_t message_len = sizeof(message);

  // Sign the same hashed point
  bssl::UniquePtr<EC_POINT> X1(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> X2(EC_POINT_new(group));
  ASSERT_EQ(voprf_message_to_point(group, &X1->raw, (const uint8_t *)message, message_len), 1);
  ASSERT_EQ(voprf_message_to_point(group, &X2->raw, (const uint8_t *)message, message_len), 1);
  EXPECT_EQ(0, EC_POINT_cmp(group, X1.get(), X2.get(), nullptr));
}

TEST(VOPRFTest, BlindSignFinalize) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  const char message[] = "hello, OPRF";
  size_t message_len = sizeof(message);

  EC_SCALAR k, r;
  ASSERT_EQ(voprf_generate_random_scalar(group, &k), 1);

  // Blind, sign, unblind
  bssl::UniquePtr<EC_POINT> R(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> M(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> N(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> T(EC_POINT_new(group));
  ASSERT_EQ(voprf_message_to_point(group, &R->raw, (const uint8_t *)message, message_len), 1);
  ASSERT_EQ(voprf_blind_point(group, &M->raw, &R->raw, &r), 1);
  ASSERT_EQ(voprf_sign_point(group, &N->raw, &M->raw, &k), 1);
  ASSERT_EQ(voprf_unblind_point(group, &T->raw, &N->raw, &r), 1);

  // Sign the same hashed point
  bssl::UniquePtr<EC_POINT> X(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> Y(EC_POINT_new(group));
  ASSERT_EQ(voprf_message_to_point(group, &X->raw, (const uint8_t *)message, message_len), 1);
  ASSERT_EQ(voprf_sign_point(group, &Y->raw, &X->raw, &k), 1);

  EXPECT_EQ(0, EC_POINT_cmp(group, X.get(), R.get(), nullptr));
  EXPECT_EQ(0, EC_POINT_cmp(group, T.get(), Y.get(), nullptr));

  // Finalize and check that the results match
  uint8_t output1[EVP_MAX_MD_SIZE] = {0};
  size_t output1_len = 0;
  ASSERT_EQ(voprf_finalize(group, output1, &output1_len, (const uint8_t *)message, message_len, &T->raw), 1);

  uint8_t output2[EVP_MAX_MD_SIZE] = {0};
  size_t output2_len = 0;
  ASSERT_EQ(voprf_finalize(group, output2, &output2_len, (const uint8_t *)message, message_len, &Y->raw), 1);

  EXPECT_EQ(Bytes(output1, output1_len), Bytes(output2, output1_len));
}

static void HexToPoint(const char *str, EC_GROUP *group, EC_RAW_POINT *out) {
  std::vector<uint8_t> ret;
  if (!DecodeHex(&ret, str)) {
    abort();
  }

  EC_AFFINE affine;
  if (!ec_point_from_uncompressed(group, &affine, ret.data(), ret.size())) {
    abort();
  }

  ec_affine_to_jacobian(group, out, &affine);
}

static void HexToScalar(const char *str, EC_GROUP *group, EC_SCALAR *out) {
  std::vector<uint8_t> ret;
  if (!DecodeHex(&ret, str)) {
    abort();
  }

  if (!ec_scalar_from_bytes(group, out, ret.data(), ret.size())) {
    abort();
  }
}

static std::vector<uint8_t> HexToBytes(const char *str) {
  std::vector<uint8_t> ret;
  if (!DecodeHex(&ret, str)) {
    abort();
  }
  return ret;
}

static uint8_t *PointToBytes(EC_GROUP *group, EC_POINT *point, size_t *output_len) {
  const size_t len =
      EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (len == 0) {
    return NULL;
  }

  uint8_t *buf = (uint8_t *)OPENSSL_malloc(len);
  if (buf == NULL) {
    return NULL;
  }

  if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL) !=
      len) {
    OPENSSL_free(buf);
    return NULL;
  }

  *output_len = len;
  return buf;
}

TEST(VOPRFTest, Vectors) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);

  const char *k_hex = "731eb0cbe382f110010d354e3fa36f6512bd056daf3f3d00996ae3ac642edb4726d410db80c2321771a93f0308ded9c9";
  // const char *r_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b";
  const char *M_hex = "0415d7f4f49f59a0e09ca9fe743f8bbdd7fbe0abb76b10b947f06db1d80f363a6292ae5cc95c0a1f59fca92eb3b9cc4779cc9fed910160cf8c150835393b4ca9c040567228a1b44bfebb426f9ecee0731f2a5be5194bfcefc6339684d5600dc44f";
  const char *y_hex = "041e71901df14f1dce45fef346b4e144ec2504d770993fff6cdfd28679201d1c875c1b69dcea661b06315f7fa8d1080d47b7708037de2282e392ffb2b175c6a3016f5066bbd733a93536a9b6284e665f69e1d70996a133f87e2e9fa7c0729e43f4";
  const char *input_hex = "00";
  std::string output_hex = "1bcf7f7b3886ce8a46581116174e27504a86bc4b582a33aeecc59bef9a922beac56febdb930cf54302a890ef6712f29540dcd58a66e262fe5cfd24541efb0264";

  EC_SCALAR k;
  HexToScalar(k_hex, group, &k);

  // Sanity check to make sure we got the right scalar
  uint8_t buf[EC_MAX_BYTES];
  size_t len;
  ec_scalar_to_bytes(group, buf, &len, &k);
  EXPECT_EQ(k_hex,
            EncodeHex(bssl::MakeConstSpan(buf, len)));

  // EC_SCALAR r;
  // HexToScalar(r_hex, group, &r);

  std::vector<uint8_t> input = HexToBytes(input_hex);
  uint8_t *input_bytes = input.data();
  size_t input_len = input.size();

  bssl::UniquePtr<EC_POINT> Y(EC_POINT_new(group));
  HexToPoint(y_hex, group, &Y->raw);

  bssl::UniquePtr<EC_POINT> M_expected(EC_POINT_new(group));
  HexToPoint(M_hex, group, &M_expected->raw);

  bssl::UniquePtr<EC_POINT> M(EC_POINT_new(group));
  ASSERT_TRUE(voprf_message_to_point(group, &M->raw, input_bytes, input_len));

  size_t M_len = 0;
  uint8_t *M_bytes = PointToBytes(group, M.get(), &M_len);
  EXPECT_EQ(M_hex,
            EncodeHex(bssl::MakeConstSpan(M_bytes, M_len)));

  EXPECT_EQ(0, EC_POINT_cmp(group, M.get(), M_expected.get(), nullptr));

  bssl::UniquePtr<EC_POINT> N(EC_POINT_new(group));
  ASSERT_TRUE(voprf_sign_point(group, &N->raw, &M->raw, &k));

  EXPECT_EQ(0, EC_POINT_cmp(group, Y.get(), N.get(), nullptr));

  uint8_t output[EVP_MAX_MD_SIZE] = {0};
  size_t output_len = 0;
  ASSERT_TRUE(voprf_finalize(group, output, &output_len, (const uint8_t *)input_bytes, input_len, &N->raw));

  EXPECT_EQ(output_hex,
            EncodeHex(bssl::MakeConstSpan(output, output_len)));
}

}  // namespace
BSSL_NAMESPACE_END
