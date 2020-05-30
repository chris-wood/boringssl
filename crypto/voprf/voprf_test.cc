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

}  // namespace
BSSL_NAMESPACE_END
