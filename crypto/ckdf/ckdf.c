/* Copyright (c) 2014, Google Inc.
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

#include <openssl/ckdf.h>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/cmac.h>
#include <openssl/cipher.h>
#include <openssl/sha.h>

#include "../internal.h"


// https://www.ietf.org/archive/id/draft-agl-ckdf-01.txt
int CKDF(uint8_t *out_key, size_t out_len, const EVP_CIPHER *cipher,
         const uint8_t *secret, size_t secret_len, const uint8_t *salt,
         size_t salt_len, const uint8_t *info, size_t info_len) {
  uint8_t prk[EVP_MAX_BLOCK_LENGTH] = {};
  size_t prk_len = 0;

  if (!CKDF_extract(prk, &prk_len, cipher, secret, secret_len, salt,
                    salt_len) ||
      !CKDF_expand(out_key, out_len, cipher, prk, prk_len, info, info_len)) {
    return 0;
  }

  return 1;
}

// https://www.ietf.org/archive/id/draft-agl-ckdf-01.txt
int CKDF_extract(uint8_t *out_key, size_t *out_len, const EVP_CIPHER *cipher,
                 const uint8_t *secret, size_t secret_len, const uint8_t *salt,
                 size_t salt_len) {

  // If salt is not given, HashLength zeros are used. However, HMAC does that
  // internally already so we can ignore it.

  // Zero-length salts should be turned into a key of length equal to the
  // corresponding cipher length.
  uint8_t zero_salt[EVP_MAX_BLOCK_LENGTH] = {0};
  if (!salt || salt_len == 0) {
    salt = zero_salt;
    salt_len = EVP_CIPHER_key_length(cipher);
  }

  // Compress down, if needed
  uint8_t key[SHA256_DIGEST_LENGTH] = {0};
  size_t key_len = EVP_CIPHER_key_length(cipher);
  SHA256(salt, salt_len, key);

  CMAC_CTX *cmac = CMAC_CTX_new();
  if (!cmac) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    return 0;
  }
  if (!CMAC_Init(cmac, key, key_len, cipher, NULL)) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    CMAC_CTX_free(cmac);
    return 0;
  }

  if (!CMAC_Update(cmac, secret, secret_len) ||
      !CMAC_Final(cmac, out_key, out_len)) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    CMAC_CTX_free(cmac);
    return 0;
  }

  CMAC_CTX_free(cmac);
  return 1;
}

#include <stdio.h>

// https://www.ietf.org/archive/id/draft-agl-ckdf-01.txt
int CKDF_expand(uint8_t *out_key, size_t out_len, const EVP_CIPHER *cipher,
                const uint8_t *prk, size_t prk_len, const uint8_t *info,
                size_t info_len) {
  const size_t block_len = EVP_CIPHER_block_size(cipher);
  uint8_t previous[EVP_MAX_BLOCK_LENGTH] = {0};

  // N = ceil(L/16)
  size_t N = (out_len + (block_len - 1)) / block_len;
  if (out_len + block_len < out_len || N > 255) {
    OPENSSL_PUT_ERROR(CKDF, CKDF_R_OUTPUT_TOO_LARGE);
    return 0;
  }

  // Compress down, if needed
  // uint8_t key[SHA256_DIGEST_LENGTH] = {0};
  // size_t key_len = EVP_CIPHER_key_length(cipher);
  // SHA256(prk, prk_len, key);
  const uint8_t *key = prk;
  size_t key_len = EVP_CIPHER_key_length(cipher);
  // printf("%zu %zu\n", prk_len, key_len);

  // T = T(1) | T(2) | T(3) | ... | T(N)
  // OKM = first L octets of T
  //
  // where:
  // T(0) = empty string (zero length)
  // T(1) = AES-CMAC(PRK, T(0) | info | 0x01)
  // T(2) = AES-CMAC(PRK, T(1) | info | 0x02)
  // T(3) = AES-CMAC(PRK, T(2) | info | 0x03)

  CMAC_CTX *cmac = CMAC_CTX_new();
  if (!cmac) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    return 0;
  }
  // CMAC_CTX cmac;

  size_t ret = 0;
  size_t done = 0;
  for (size_t i = 0; i < N; i++) {
    uint8_t ctr = i + 1;
    size_t todo;

    if (!CMAC_Init(cmac, key, key_len, cipher, NULL) ||
        !CMAC_Update(cmac, previous, block_len)) {
      OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
      goto out;
    }
    if (!CMAC_Update(cmac, info, info_len) ||
        !CMAC_Update(cmac, &ctr, 1) ||
        !CMAC_Final(cmac, previous, &todo)) {
      OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
      goto out;
    }

    if (done + todo > out_len) {
      todo = out_len - done;
    }
    OPENSSL_memcpy(out_key + done, previous, todo);
    done += todo;
  }

  ret = 1;

out:
  CMAC_CTX_free(cmac);
  if (ret != 1) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
  }
  return ret;
}
