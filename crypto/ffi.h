/* Copyright 2015 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef RING_HEADER_CRYPTO_FFI_H
#define RING_HEADER_CRYPTO_FFI_H

/* The *ring* FFI consistency interface provides a means for ensuring that
 * C and Rust definitions of structs match.
 *
 * # Example:
 *
 * ```C
 * struct foo_foo {
 *   // Keep this in sync with |ring::foo::foo| and the metadata below.
 *   uint64_t bar[12];
 *   int baz;
 * };
 *
 * RING_BEGIN_STRUCT_METADATA(foo_foo)
 *   RING_MEMBER_METADATA(foo_foo, bar)
 *   RING_MEMBER_METADATA(foo_foo, baz)
 * RING_END_STRUCT_METADATA(foo_foo)
 * ```
 *
 * ```rust
 *
 * use libc;
 *
 * #[macro_use(checked_struct)]
 * use ring::ffi;
 *
 * checked_struct!{
 *     struct foo_foo {
 *         bar: [u64; 12],
 *         baz: libc::c_int,
 *     },
 *     test_foo_foo_struct_consistency,
 *     ring_ffi_foo_foo_metadata
 * }
 * ```
 */

#define RING_BEGIN_STRUCT_METADATA(struct_name)
#define RING_MEMBER_METADATA(struct_name, member_name)
#define RING_END_STRUCT_METADATA(struct_name)

#endif
