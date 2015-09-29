// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include "ffi.h"

/* Do not include any *ring* headers here other than ffi.h. *ring* headers must
 * only be included after the |RING_*_METADATA| macros have been defined near
 * the end of this file. */

#include <stddef.h>

struct ring_ffi_struct_metadata {
  // Keep in sync with |ring::ffi|.
  const char *name;
  size_t size;
  size_t alignment;

  /* The array is terminated by an element with a |NULL| name. */
  const struct struct_member_metadata *members;
};

struct ring_ffi_struct_member_metadata {
  // Keep in sync with |ring::ffi|.
  const char *name;
  size_t offset;
};

#if defined(_MSC_VER)
#define RING_ALIGNOF __alignof
#else
#define RING_ALIGNOF _Alignof
#endif

#define RING_META_META_STRUCT(struct_name) \
        size_t struct_name##_size(void) { \
            return sizeof(struct struct_name); \
        } \
        \
        size_t struct_name##_alignment(void) { \
            return RING_ALIGNOF(struct struct_name); \
        }

#define RING_META_META_MEMBER(struct_name, member_name) \
        size_t struct_name##_##member_name##_offset(void) { \
            return offsetof(struct struct_name, member_name); \
        }

RING_META_META_STRUCT(ring_ffi_struct_metadata)
RING_META_META_MEMBER(ring_ffi_struct_metadata, name)
RING_META_META_MEMBER(ring_ffi_struct_metadata, size)
RING_META_META_MEMBER(ring_ffi_struct_metadata, alignment)
RING_META_META_MEMBER(ring_ffi_struct_metadata, members)

RING_META_META_STRUCT(ring_ffi_struct_member_metadata)
RING_META_META_MEMBER(ring_ffi_struct_member_metadata, name)
RING_META_META_MEMBER(ring_ffi_struct_member_metadata, offset)

/* These macros are defined in ffi.h to expand to nothing. However, now we need
 * them to expand into the definitions of the metadata functions. */

#undef RING_BEGIN_STRUCT_METADATA
#define RING_BEGIN_STRUCT_METADATA(struct_name) \
        const struct ring_ffi_struct_metadata \
        *ring_ffi_##struct_name##_metadata(void) { \
          static const struct ring_ffi_struct_metadata METADATA = { \
            #struct_name, \
            sizeof(struct struct_name), \
            ALIGNOF(struct struct_name), \
            { \

#undef RING_MEMBER_METADATA
#define RING_MEMBER_METADATA(struct_name, member_name) \
              { #member_name, offsetof(struct struct_name, member_name) }

#undef RING_END_STRUCT_METADATA
#define RING_END_STRUCT_METADATA(struct_name) \
              { NULL, 0 } \
            } \
          }; \
          return &METADATA; \
        }
