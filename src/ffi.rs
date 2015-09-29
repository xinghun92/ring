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

use libc;

#[cfg(test)]
use std;

pub fn map_bssl_result(bssl_result: libc::c_int) -> Result<(), ()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(())
    }
}

pub fn map_bssl_ptr_result<T>(bssl_result: *mut T) -> Result<*mut T, ()> {
    if bssl_result.is_null() {
        return Err(());
    }
    Ok(bssl_result)
}


/// Returns `Ok(())` of `a == b` and `Err(())` otherwise. The comparison of
/// `a` and `b` is done in constant time with respect to the contents of each,
/// but NOT in constant time with respect to the lengths of `a` and `b`.
pub fn verify_slices_are_equal_ct(a: &[u8], b: &[u8]) -> Result<(), ()> {
    if a.len() != b.len() {
        return Err(());
    }
    let result = unsafe {
        CRYPTO_memcmp(a.as_ptr(), b.as_ptr(), a.len() as libc::size_t)
    };
    match result {
        0 => Ok(()),
        _ => Err(())
    }
}

macro_rules! offset_of {
    ($ty:ty, $member:ident) => {
        {
            let dummy: $ty = unsafe { std::mem::uninitialized() };
            let base_offset = &dummy as *const _ as usize;
            let member_offset = &dummy.$member as *const _ as usize;
            member_offset - base_offset
        }
    }
}

extern {
    fn CRYPTO_memcmp(a: *const libc::uint8_t, b: *const libc::uint8_t,
                     len: libc::size_t) -> libc::c_int;
}

/// Declares a struct. the struct's size and alignment, as well as the
/// offset of each member, are checked by a test function defined by the
/// macro which calls the given extern function. The extern function is given
/// the size of the Rust struct, the alignment of the Rust struct, and the
/// offsets of all the members of the Rust struct. The extern function can then
/// verify thta the size, alignment, and member offsets all match the C
/// definitions.
///
/// # Example
///
/// ```ignore
/// #[macro_use(checked_struct)]
/// use ring::ffi;
///
/// checked_struct!{
///     struct Foo {
///         foo: u8,
///         bar: u64,
///     },
///     test_foo_size_alignment_and_offsets,
///     foreign_api_check_foo_size_alignment_and_offsets,
/// }
/// ```
///
/// In this example, the struct `Foo` will be defined according to the
/// definition embedded in the macro invocation. A `#[test]` function
/// `test_foo_size_alignment_and_offsets` will also be defined that will call
/// `foreign_api_check_foo_size_alignment_and_offsets(
///     std::mem::size_of::<Foo>() as libc::size_t,
///     std::mem::align_of::<Foo>() as libc::size_t,
///     "foo".as_ptr(), "foo".len() as libc::size_t, offset_of!(Foo, foo),
///     "bar".as_ptr(), "bar".len() as libc::size_t, offset_of!(Foo, bar))`,
/// asserting that the result is 1. The function
/// `foreign_api_check_foo_size_alignment_and_offsets` needs to be implemented
/// manually. It should return 1 if the size, alignment, and all offsets match
/// the C definition of the struct, and 0 otherwise.
#[macro_export]
macro_rules! checked_struct {
    // Handle non-public structs.
    (   struct $name:ident {
            $( $member_name:ident: $member_type:ty, )*
        },
        $test_fn:ident,
        $ffi_fn:ident
    ) => {
        checked_struct!{
            DECLARE #![repr(C)] struct $name {
                $( $member_name: $member_type, )*
            }
        }

        checked_struct!{
            CHECK $test_fn, $ffi_fn, $name ( $( $member_name ),* )
        }
    };

    // Declare the struct by outputting the input struct declaration.
    (   DECLARE
        struct $name:ident {
            $( $member_name:ident: $member_type:ty, )*
        }
    ) => {
        #![allow(non_snake_case)]
        #![repr(C)]
        struct $name {
            $( $member_name: $member_type, )*
        }
    };

    // Define the test function `$test_fn`.
    (   CHECK
        $test_fn:ident,
        $ffi_fn:ident,
        $name:ident ( $( $member_name:ident ),* )
    ) => {
        #[cfg(test)]
        extern {
            #![allow(non_snake_case)]
            fn $ffi_fn() -> libc::c_int;
        }

        #![allow(non_snake_case)]
        #[cfg(test)]
        #[test]
        fn $test_fn() {
            let result =
                $ffi_fn(std::mem::size_of::<$name>(),
                        std::mem::align_of::<$name>(),
                        $( stringify!($member_name),
                           offset_of!($name, $member_name)
                         ),*);
            assert_eq!(1, result)
        }
    }
}

/// An analog to C's `offsetof` macro. The main difference from C's `offsetof`
/// is that this macro doesn't expand to a constant expression.
macro_rules! offset_of {
    ($ty:ty, $member:ident) => {
        {
            let dummy: $ty = unsafe { std::mem::uninitialized() };
            let base_offset = &dummy as *const _ as usize;
            let member_offset = &dummy.$member as *const _ as usize;
            member_offset - base_offset
        }
    }
}

#[cfg(test)]
pub fn assert_struct_definition_matches<T>(
        name: &'static str, other_side: *const ring_ffi_struct_metadata) {
    unsafe {
        assert_eq!(name.as_bytes(),
                    std::ffi::CStr::from_ptr((*other_side).name).to_bytes());
        assert_eq!(std::mem::size_of::<T>(), (*other_side).size as usize);
        assert_eq!(std::mem::align_of::<T>(),
                    (*other_side).alignment as usize);
    }
}

#[cfg(test)]
pub fn assert_struct_member_definition_matches(
        name: &'static str, offset: usize,
        other_side: *const ring_ffi_struct_member_metadata) {
    unsafe {
        assert_eq!(name.as_bytes(),
                    std::ffi::CStr::from_ptr((*other_side).name).to_bytes());
        assert_eq!(offset, (*other_side).offset as usize);
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
#[repr(C)]
pub struct ring_ffi_struct_metadata {
    // Keep in sync with crypto/test/ring_ffi_test.c and
    // `test_ffi_struct_metadata_consistency` below.
    name: *const libc::c_char,
    size: libc::size_t,
    alignment: libc::size_t,

    /// A pointer to an array of field metadata structs. The array is
    /// terminated by an entry with a `NULL` name.
    members: *const ring_ffi_struct_member_metadata
}

#[allow(non_snake_case)]
#[cfg(test)]
#[repr(C)]
pub struct ring_ffi_struct_member_metadata {
    // Keep in sync with crypto/test/ring_ffi_test.c and
    // `test_ffi_struct_metadata_consistency` below.
    name: *const libc::c_char,
    offset: libc::size_t,
}

#[cfg(test)]
mod tests {
    use libc;
    use std;
    use super::{ring_ffi_struct_metadata, ring_ffi_struct_member_metadata};

    #[test]
    fn test_ffi_struct_metadata_consistency() {
        // We cannot use `checked_struct!` to define the `ffi_struct_metadata`
        // and `ring_ffi_Struct_metadata`, so we have to test the consistency
        // in a more manual way.
        assert_eq!(std::mem::size_of::<ring_ffi_struct_metadata>(),
                   unsafe { ring_ffi_struct_metadata_size() as usize });
        assert_eq!(std::mem::align_of::<ring_ffi_struct_metadata>(),
                   unsafe { ring_ffi_struct_metadata_alignment() as usize });
        assert_eq!(offset_of!(ring_ffi_struct_metadata, name),
                   unsafe { ring_ffi_struct_metadata_name_offset() as usize });
        assert_eq!(offset_of!(ring_ffi_struct_metadata, size),
                   unsafe { ring_ffi_struct_metadata_size_offset() as usize });
        assert_eq!(offset_of!(ring_ffi_struct_metadata, alignment),
                   unsafe {
                        ring_ffi_struct_metadata_alignment_offset() as usize
                    });

        assert_eq!(std::mem::size_of::<ring_ffi_struct_member_metadata>(),
                   unsafe { ring_ffi_struct_member_metadata_size() as usize });
        assert_eq!(std::mem::align_of::<ring_ffi_struct_member_metadata>(),
                   unsafe {
                        ring_ffi_struct_member_metadata_alignment() as usize
                   });
        assert_eq!(offset_of!(ring_ffi_struct_member_metadata, name),
                   unsafe {
                        ring_ffi_struct_member_metadata_name_offset() as usize
                   });
        assert_eq!(offset_of!(ring_ffi_struct_member_metadata, offset),
                   unsafe {
                        ring_ffi_struct_member_metadata_offset_offset()
                            as usize
                    });
    }

    extern {
        fn ring_ffi_struct_metadata_size() -> libc::size_t;
        fn ring_ffi_struct_metadata_alignment() -> libc::size_t;
        fn ring_ffi_struct_metadata_name_offset() -> libc::size_t;
        fn ring_ffi_struct_metadata_size_offset() -> libc::size_t;
        fn ring_ffi_struct_metadata_alignment_offset() -> libc::size_t;
        fn ring_ffi_struct_metadata_members_offset() -> libc::size_t;
        fn ring_ffi_struct_member_metadata_size() -> libc::size_t;
        fn ring_ffi_struct_member_metadata_alignment() -> libc::size_t;
        fn ring_ffi_struct_member_metadata_name_offset() -> libc::size_t;
        fn ring_ffi_struct_member_metadata_offset_offset() -> libc::size_t;
    }
}
