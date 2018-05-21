/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "internal.h"
#include "../../internal.h"
#include "../../limbs/limbs.h"

// |BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE| will be 6 in some cases and
// that likely means 5 would be suboptimal. TODO: measure and optimize this.
static const int window = 5;

// Half the size of the largest supported public modulus, in limbs.
#define PRIVATE_MODULUS_MAX_LIMBS (8192 / 2 / BN_BITS2)

// Prototypes to avoid -Wmissing-prototypes warnings.
size_t GFp_BN_mod_exp_mont_consttime_powerbuf_len(size_t top);
int GFp_BN_mod_exp_mont_consttime(BN_ULONG rr[], const BN_ULONG a_mont[],
                                  const BN_ULONG p[], const BN_ULONG one_mont[],
                                  const BN_ULONG n[], size_t num_limbs,
                                  const BN_ULONG n0[BN_MONT_CTX_N0_LIMBS],
                                  BN_ULONG powerbuf_unaligned[],
                                  size_t powerbuf_unaligned_len);
const size_t GFp_PRIVATE_MODULUS_MAX_LIMBS = PRIVATE_MODULUS_MAX_LIMBS;

#if defined(OPENSSL_X86_64)
#define OPENSSL_BN_ASM_MONT5
#endif

void GFp_bn_mul_mont_gather5(BN_ULONG rp[], const BN_ULONG ap[],
                             const BN_ULONG table[], const BN_ULONG np[],
                             const BN_ULONG n0[], size_t num, size_t power);
void GFp_bn_scatter5(const BN_ULONG inp[], size_t num, BN_ULONG table[],
                     size_t power);
void GFp_bn_gather5(BN_ULONG out[], size_t num, const BN_ULONG table[],
                    size_t power);
void GFp_bn_power5(BN_ULONG rp[], const BN_ULONG ap[], const BN_ULONG table[],
                   const BN_ULONG np[], const BN_ULONG n0[], size_t num,
                   size_t power);

#if defined(OPENSSL_BN_ASM_MONT5)
int GFp_bn_from_montgomery(BN_ULONG rp[], const BN_ULONG ap[],
                           const BN_ULONG *not_used, const BN_ULONG np[],
                           const BN_ULONG n0[], int num);
#endif

// GFp_BN_mod_exp_mont_consttime() stores the precomputed powers in a specific
// layout so that accessing any of these table values shows the same access
// pattern as far as cache lines are concerned. The following functions are
// used to transfer a BIGNUM from/to that table.
#if !defined(OPENSSL_BN_ASM_MONT5)

void GFp_bn_scatter5(const BN_ULONG b[], size_t top, BN_ULONG table[],
                     size_t power) {
  assert(window == 5);

  size_t i, j;
  const size_t width = 1u << window;
  for (i = 0, j = power; i < top; i++, j += width)  {
    table[j] = b[i];
  }
}

void GFp_bn_gather5(BN_ULONG b[], size_t top, const BN_ULONG buf[],
                    size_t power) {
  assert(window == 5);

  size_t i, j;
  const size_t width = 1u << window;
  volatile const BN_ULONG *table = (volatile const BN_ULONG *)buf;

  assert(window > 3);
  size_t xstride = 1u << (window - 2);
  BN_ULONG y0, y1, y2, y3;

  size_t idx = power;

  i = idx >> (window - 2);  // equivalent of idx / xstride
  idx &= xstride - 1;       // equivalent of idx % xstride

  y0 = (BN_ULONG)0 - (constant_time_eq_int(i, 0) & 1);
  y1 = (BN_ULONG)0 - (constant_time_eq_int(i, 1) & 1);
  y2 = (BN_ULONG)0 - (constant_time_eq_int(i, 2) & 1);
  y3 = (BN_ULONG)0 - (constant_time_eq_int(i, 3) & 1);

  for (i = 0; i < top; i++, table += width) {
    BN_ULONG acc = 0;

    for (j = 0; j < xstride; j++) {
      acc |= ((table[j + 0 * xstride] & y0) | (table[j + 1 * xstride] & y1) |
              (table[j + 2 * xstride] & y2) | (table[j + 3 * xstride] & y3)) &
             ((BN_ULONG)0 - (constant_time_eq_int(j, idx) & 1));
    }

    b[i] = acc;
  }
}
#endif

// GFp_BN_mod_exp_mont_consttime is based on the assumption that the L1 data cache
// line width of the target processor is at least the following value.
#define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH 64
#define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK \
  ((MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH) - 1)

// Window sizes optimized for fixed window size modular exponentiation
// algorithm (GFp_BN_mod_exp_mont_consttime).
//
// To achieve the security goals of GFp_BN_mod_exp_mont_consttime, the maximum
// size of the window must not exceed
// log_2(MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH).
//
// Window size thresholds are defined for cache line sizes of 32 and 64, cache
// line sizes where log_2(32)=5 and log_2(64)=6 respectively. A window size of
// 7 should only be used on processors that have a 128 byte or greater cache
// line size.
#if MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 64
#define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE (6)
#elif MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 32
#define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE (5)
#endif

// Given a pointer value, compute the next address that is a cache line
// multiple.
#define MOD_EXP_CTIME_ALIGN(x_)          \
  ((unsigned char *)(x_) +               \
   (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - \
    (((uintptr_t)(x_)) & ((uintptr_t)MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

#if !defined(OPENSSL_BN_ASM_MONT5)

void GFp_bn_mul_mont_gather5(BN_ULONG rp[], const BN_ULONG ap[],
                             const BN_ULONG table[], const BN_ULONG np[],
                             const BN_ULONG n0[], size_t num, size_t power) {
  // The |OPENSSL_BN_ASM_MONT5| version doesn't require |rp != ap| but this
  // version does, so we can gather into rp.
  assert(rp != ap);
  GFp_bn_gather5(rp, num, table, power);
  GFp_bn_mul_mont(rp, rp, ap, np, n0, num);
}

void GFp_bn_power5(BN_ULONG rp[], const BN_ULONG ap[], const BN_ULONG table[],
                   const BN_ULONG np[], const BN_ULONG n0[], size_t num,
                   size_t power) {
  // The |OPENSSL_BN_ASM_MONT5| version requires that the number of (64-bit)
  // limbs must be divisible by 8.
  assert((num * BN_BITS2) % 512 == 0);
  alignas(MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH) BN_ULONG
    tmp[PRIVATE_MODULUS_MAX_LIMBS];
  assert(num <= PRIVATE_MODULUS_MAX_LIMBS);

  GFp_bn_mul_mont(tmp, ap, ap, np, n0, num);
  for (size_t i = 1; i < 5; ++i) {
    GFp_bn_mul_mont(tmp, tmp, tmp, np, n0, num);
  }

  GFp_bn_mul_mont_gather5(rp, tmp, table, np, n0, num, power);
}

#endif

size_t GFp_BN_mod_exp_mont_consttime_powerbuf_len(size_t top) {
  // Allocate a buffer large enough to hold all of the pre-computed
  // powers of am, am itself and tmp.
  size_t numPowers = (size_t)1u << window;
  size_t powerbuf_len =
    (top * numPowers + ((2 * top) > numPowers ? (2 * top) : numPowers));

  // Reserve space for |n| copy.
  powerbuf_len += top;

  // Reserve space for the alignment correction.
  powerbuf_len += MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH;

  return powerbuf_len;
}

// This variant of GFp_BN_mod_exp_mont() uses fixed windows and the special
// precomputation memory layout to limit data-dependency to a minimum
// to protect secret exponents (cf. the hyper-threading timing attacks
// pointed out by Colin Percival,
// http://www.daemonology.net/hyperthreading-considered-harmful/).
//
// |p| must be positive. |a_mont| must in [0, m). |one_mont| must be
// the value 1 Montgomery-encoded and fully reduced (mod m).
//
// Assumes 0 < a_mont < n, 0 < p, 0 < p_bits.
int GFp_BN_mod_exp_mont_consttime(BN_ULONG rr[], const BN_ULONG a_mont[],
                                  const BN_ULONG p[], const BN_ULONG one_mont[],
                                  const BN_ULONG n[], size_t num_limbs,
                                  const BN_ULONG n0[BN_MONT_CTX_N0_LIMBS],
                                  BN_ULONG powerbuf_unaligned[],
                                  size_t powerbuf_unaligned_len) {
  if (powerbuf_unaligned_len !=
         GFp_BN_mod_exp_mont_consttime_powerbuf_len(num_limbs)) {
    return 0;
  }
  if (!GFp_bn_mul_mont_check_num_limbs(num_limbs)) {
    return 0;
  }
  // |GFp_bn_power5| and |GFp_bn_from_montgomery| require this.
  if ((num_limbs * BN_BITS2) % 512 != 0) {
    return 0;
  }
  // The C implementation of |GFp_bn_power5| requires this. Also, this bounds
  // the stack usage from the hidden |alloca()| calls in the
  // |OPENSSL_BN_ASM_MONT5|.
  if (num_limbs > PRIVATE_MODULUS_MAX_LIMBS) {
    return 0;
  }

  int i, wvalue;

  const int top = (int) num_limbs;

  // Use all bits stored in |p|, rather than |BN_num_bits|, so we do not leak
  // whether the top bits are zero.
  int max_bits = (int) num_limbs * BN_BITS2;
  int bits = max_bits;
  assert(bits > 0);

  assert(window == 5);
  assert(window <= BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE);

  BN_ULONG *powerbuf = (BN_ULONG *)MOD_EXP_CTIME_ALIGN(powerbuf_unaligned);

  size_t numPowers = (size_t)1u << window;

  // Lay down tmp and am right after powers table.
  BN_ULONG *tmp = powerbuf + (top * numPowers);
  BN_ULONG *am = tmp + top;

  // Copy a^0 and a^1.
  LIMBS_copy(tmp, one_mont, num_limbs);
  LIMBS_copy(am, a_mont, num_limbs);

  // copy n[] to improve cache locality
  BN_ULONG *np = am + top;
  LIMBS_copy(np, n, num_limbs);

  // Use the precomputation from http://eprint.iacr.org/2011/239.
  {
    GFp_bn_scatter5(tmp, top, powerbuf, 0);
    GFp_bn_scatter5(am, top, powerbuf, 1);
    GFp_bn_mul_mont(tmp, am, am, np, n0, top);
    GFp_bn_scatter5(tmp, top, powerbuf, 2);

    // same as above, but uses squaring for 1/2 of operations
    for (i = 4; i < 32; i *= 2) {
      GFp_bn_mul_mont(tmp, tmp, tmp, np, n0, top);
      GFp_bn_scatter5(tmp, top, powerbuf, i);
    }
    for (i = 3; i < 8; i += 2) {
      int j;
      GFp_bn_mul_mont_gather5(tmp, am, powerbuf, np, n0, top, i - 1);
      GFp_bn_scatter5(tmp, top, powerbuf, i);
      for (j = 2 * i; j < 32; j *= 2) {
        GFp_bn_mul_mont(tmp, tmp, tmp, np, n0, top);
        GFp_bn_scatter5(tmp, top, powerbuf, j);
      }
    }
    for (; i < 16; i += 2) {
      GFp_bn_mul_mont_gather5(tmp, am, powerbuf, np, n0, top, i - 1);
      GFp_bn_scatter5(tmp, top, powerbuf, i);
      GFp_bn_mul_mont(tmp, tmp, tmp, np, n0, top);
      GFp_bn_scatter5(tmp, top, powerbuf, 2 * i);
    }
    for (; i < 32; i += 2) {
      GFp_bn_mul_mont_gather5(tmp, am, powerbuf, np, n0, top, i - 1);
      GFp_bn_scatter5(tmp, top, powerbuf, i);
    }
  }

  // This optimization uses ideas from http://eprint.iacr.org/2011/239,
  // specifically optimization of cache-timing attack countermeasures
  // and pre-computation optimization.
  {
    bits--;
    for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--) {
      wvalue = (wvalue << 1) + GFp_bn_is_bit_set_words(p, num_limbs, bits);
    }
    GFp_bn_gather5(tmp, top, powerbuf, wvalue);

    // At this point |bits| is 4 mod 5 and at least -1. (|bits| is the first bit
    // that has not been read yet.)
    assert(bits >= -1 && (bits == -1 || bits % 5 == 4));

    // Scan the exponent one window at a time starting from the most
    // significant bits.
    {
      const aliasing_uint8 *p_bytes = (const aliasing_uint8 *)p;
      assert(bits < max_bits);
      // |p = 0| has been handled as a special case, so |max_bits| is at least
      // one word.
      assert(max_bits >= 64);

      // If the first bit to be read lands in the last byte, unroll the first
      // iteration to avoid reading past the bounds of |p|. (After the first
      // iteration, we are guaranteed to be past the last byte.) Note |bits|
      // here is the top bit, inclusive.
      if (bits - 4 >= max_bits - 8) {
        // Read five bits from |bits-4| through |bits|, inclusive.
        wvalue = p_bytes[num_limbs * sizeof(Limb) - 1];
        wvalue >>= (bits - 4) & 7;
        wvalue &= 0x1f;
        bits -= 5;
        GFp_bn_power5(tmp, tmp, powerbuf, np, n0, top, wvalue);
      }
      while (bits >= 0) {
        // Read five bits from |bits-4| through |bits|, inclusive.
        int first_bit = bits - 4;
        uint16_t val;
        // Assumes little-endian.
        memcpy(&val, p_bytes + (first_bit >> 3), sizeof(val));
        val >>= first_bit & 7;
        val &= 0x1f;
        bits -= 5;
        GFp_bn_power5(tmp, tmp, powerbuf, np, n0, top, val);
      }
    }

#if defined(OPENSSL_BN_ASM_MONT5)
    if (!GFp_bn_from_montgomery(tmp, tmp, NULL, np, n0, top)) {
      return 0;
    }
#endif
  }
  LIMBS_copy(rr, tmp, top);

  return 1;
}
