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

#include "../internal.h"


int CKDF(uint8_t *out_key, size_t out_len, const EVP_CIPHER *cipher,
         const uint8_t *secret, size_t secret_len, const uint8_t *salt,
         size_t salt_len, const uint8_t *info, size_t info_len) {
  // TODO(caw): reference to CKDF
  uint8_t prk[EVP_MAX_BLOCK_LENGTH];
  size_t prk_len;

  if (!CKDF_extract(prk, &prk_len, cipher, secret, secret_len, salt,
                    salt_len) ||
      !CKDF_expand(out_key, out_len, cipher, prk, prk_len, info, info_len)) {
    return 0;
  }

  return 1;
}

int CKDF_extract(uint8_t *out_key, size_t *out_len, const EVP_CIPHER *cipher,
                 const uint8_t *secret, size_t secret_len, const uint8_t *salt,
                 size_t salt_len) {
  // https://tools.ietf.org/html/rfc5869#section-2.2

  // If salt is not given, HashLength zeros are used. However, HMAC does that
  // internally already so we can ignore it.

  // TODO(caw): check for empty salt/salt_len
  // TODO(caw): implement CBC-MAC?

  // int AES_CMAC(uint8_t out[16], const uint8_t *key, size_t key_len,
  //                           const uint8_t *in, size_t in_len)

  CMAC_CTX *cmac = CMAC_CTX_new();
  if (!cmac) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    return 0;
  }
  if (!CMAC_Init(cmac, secret, secret_len, cipher, NULL)) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    CMAC_CTX_free(cmac);
    return 0;
  }

  if (!CMAC_Update(cmac, salt, salt_len) ||
      !CMAC_Final(cmac, out_key, out_len)) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    CMAC_CTX_free(cmac);
    return 0;
  }

  // unsigned len;
  // if (HMAC(digest, salt, salt_len, secret, secret_len, out_key, &len) == NULL) {
  //   OPENSSL_PUT_ERROR(HKDF, ERR_R_HMAC_LIB);
  //   return 0;
  // }
  // *out_len = len;
  // assert(*out_len == EVP_MD_size(digest));

  CMAC_CTX_free(cmac);
  return 1;
}

int CKDF_expand(uint8_t *out_key, size_t out_len, const EVP_CIPHER *cipher,
                const uint8_t *prk, size_t prk_len, const uint8_t *info,
                size_t info_len) {
  // https://tools.ietf.org/html/rfc5869#section-2.3
  const size_t digest_len = EVP_CIPHER_block_size(cipher);
  uint8_t previous[EVP_MAX_BLOCK_LENGTH];
  size_t n, done = 0;
  unsigned i;
  int ret = 0;
  // HMAC_CTX hmac;
  CMAC_CTX *cmac;

  // Expand key material to desired length.
  n = (out_len + digest_len - 1) / digest_len;
  if (out_len + digest_len < out_len || n > 255) {
    OPENSSL_PUT_ERROR(CKDF, CKDF_R_OUTPUT_TOO_LARGE);
    return 0;
  }

  // CMAC_CTX_init(&cmac);
  // if (!CMAC_Init_ex(&cmac, prk, prk_len, digest, NULL)) {
  //   goto out;
  // }

  cmac = CMAC_CTX_new();
  if (!cmac) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
    return 0;
  }

  if (!CMAC_Init(cmac, prk, prk_len, cipher, NULL)) {
    goto out;
  }

  for (i = 0; i < n; i++) {
    uint8_t ctr = i + 1;
    size_t todo;

    if (i != 0 && (!CMAC_Init(cmac, prk, prk_len, cipher, NULL) ||
                   !CMAC_Update(cmac, previous, digest_len))) {
      goto out;
    }
    if (!CMAC_Update(cmac, info, info_len) ||
        !CMAC_Update(cmac, &ctr, 1) ||
        !CMAC_Final(cmac, previous, NULL)) {
      goto out;
    }

    todo = digest_len;
    if (done + todo > out_len) {
      todo = out_len - done;
    }
    OPENSSL_memcpy(out_key + done, previous, todo);
    done += todo;
  }

  ret = 1;

out:
  // HMAC_CTX_cleanup(&hmac);
  CMAC_CTX_free(cmac);
  if (ret != 1) {
    OPENSSL_PUT_ERROR(CKDF, ERR_R_CMAC_LIB);
  }
  return ret;
}
