// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::usercopy::*;
use alloc::format;

#[test]
fn test_usercopy_error_null_pointer_variant() {
    let err = UsercopyError::NullPointer;
    assert_eq!(err, UsercopyError::NullPointer);
}

#[test]
fn test_usercopy_error_invalid_address_variant() {
    let err = UsercopyError::InvalidAddress;
    assert_eq!(err, UsercopyError::InvalidAddress);
}

#[test]
fn test_usercopy_error_address_overflow_variant() {
    let err = UsercopyError::AddressOverflow;
    assert_eq!(err, UsercopyError::AddressOverflow);
}

#[test]
fn test_usercopy_error_page_not_mapped_variant() {
    let err = UsercopyError::PageNotMapped;
    assert_eq!(err, UsercopyError::PageNotMapped);
}

#[test]
fn test_usercopy_error_page_not_user_variant() {
    let err = UsercopyError::PageNotUser;
    assert_eq!(err, UsercopyError::PageNotUser);
}

#[test]
fn test_usercopy_error_page_not_writable_variant() {
    let err = UsercopyError::PageNotWritable;
    assert_eq!(err, UsercopyError::PageNotWritable);
}

#[test]
fn test_usercopy_error_page_fault_variant() {
    let err = UsercopyError::PageFault;
    assert_eq!(err, UsercopyError::PageFault);
}

#[test]
fn test_usercopy_error_no_process_context_variant() {
    let err = UsercopyError::NoProcessContext;
    assert_eq!(err, UsercopyError::NoProcessContext);
}

#[test]
fn test_usercopy_error_size_too_large_variant() {
    let err = UsercopyError::SizeTooLarge;
    assert_eq!(err, UsercopyError::SizeTooLarge);
}

#[test]
fn test_usercopy_error_variants_not_equal() {
    assert_ne!(UsercopyError::NullPointer, UsercopyError::InvalidAddress);
    assert_ne!(UsercopyError::AddressOverflow, UsercopyError::PageNotMapped);
    assert_ne!(UsercopyError::PageNotUser, UsercopyError::PageNotWritable);
    assert_ne!(UsercopyError::PageFault, UsercopyError::NoProcessContext);
    assert_ne!(UsercopyError::SizeTooLarge, UsercopyError::NullPointer);
}

#[test]
fn test_usercopy_error_clone() {
    let err = UsercopyError::PageFault;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_usercopy_error_copy() {
    let err = UsercopyError::InvalidAddress;
    let copied = err;
    assert_eq!(err, copied);
}

#[test]
fn test_usercopy_error_display_null_pointer() {
    let err = UsercopyError::NullPointer;
    assert_eq!(format!("{}", err), "null pointer");
}

#[test]
fn test_usercopy_error_display_invalid_address() {
    let err = UsercopyError::InvalidAddress;
    assert_eq!(format!("{}", err), "invalid user address");
}

#[test]
fn test_usercopy_error_display_address_overflow() {
    let err = UsercopyError::AddressOverflow;
    assert_eq!(format!("{}", err), "address overflow");
}

#[test]
fn test_usercopy_error_display_page_not_mapped() {
    let err = UsercopyError::PageNotMapped;
    assert_eq!(format!("{}", err), "page not mapped");
}

#[test]
fn test_usercopy_error_display_page_not_user() {
    let err = UsercopyError::PageNotUser;
    assert_eq!(format!("{}", err), "page not accessible from userspace");
}

#[test]
fn test_usercopy_error_display_page_not_writable() {
    let err = UsercopyError::PageNotWritable;
    assert_eq!(format!("{}", err), "page not writable");
}

#[test]
fn test_usercopy_error_display_page_fault() {
    let err = UsercopyError::PageFault;
    assert_eq!(format!("{}", err), "page fault during access");
}

#[test]
fn test_usercopy_error_display_no_process_context() {
    let err = UsercopyError::NoProcessContext;
    assert_eq!(format!("{}", err), "no process context");
}

#[test]
fn test_usercopy_error_display_size_too_large() {
    let err = UsercopyError::SizeTooLarge;
    assert_eq!(format!("{}", err), "copy size too large");
}

#[test]
fn test_usercopy_error_debug_null_pointer() {
    let err = UsercopyError::NullPointer;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("NullPointer"));
}

#[test]
fn test_usercopy_error_debug_invalid_address() {
    let err = UsercopyError::InvalidAddress;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidAddress"));
}

#[test]
fn test_usercopy_error_debug_address_overflow() {
    let err = UsercopyError::AddressOverflow;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("AddressOverflow"));
}

#[test]
fn test_usercopy_error_debug_page_not_mapped() {
    let err = UsercopyError::PageNotMapped;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("PageNotMapped"));
}

#[test]
fn test_usercopy_error_debug_page_not_user() {
    let err = UsercopyError::PageNotUser;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("PageNotUser"));
}

#[test]
fn test_usercopy_error_debug_page_not_writable() {
    let err = UsercopyError::PageNotWritable;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("PageNotWritable"));
}

#[test]
fn test_usercopy_error_debug_page_fault() {
    let err = UsercopyError::PageFault;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("PageFault"));
}

#[test]
fn test_usercopy_error_debug_no_process_context() {
    let err = UsercopyError::NoProcessContext;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("NoProcessContext"));
}

#[test]
fn test_usercopy_error_debug_size_too_large() {
    let err = UsercopyError::SizeTooLarge;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("SizeTooLarge"));
}

#[test]
fn test_usercopy_error_equality_same_variant() {
    assert_eq!(UsercopyError::NullPointer, UsercopyError::NullPointer);
    assert_eq!(UsercopyError::InvalidAddress, UsercopyError::InvalidAddress);
    assert_eq!(UsercopyError::AddressOverflow, UsercopyError::AddressOverflow);
    assert_eq!(UsercopyError::PageNotMapped, UsercopyError::PageNotMapped);
    assert_eq!(UsercopyError::PageNotUser, UsercopyError::PageNotUser);
    assert_eq!(UsercopyError::PageNotWritable, UsercopyError::PageNotWritable);
    assert_eq!(UsercopyError::PageFault, UsercopyError::PageFault);
    assert_eq!(UsercopyError::NoProcessContext, UsercopyError::NoProcessContext);
    assert_eq!(UsercopyError::SizeTooLarge, UsercopyError::SizeTooLarge);
}

#[test]
fn test_usercopy_error_all_variants_unique_display() {
    let variants = [
        UsercopyError::NullPointer,
        UsercopyError::InvalidAddress,
        UsercopyError::AddressOverflow,
        UsercopyError::PageNotMapped,
        UsercopyError::PageNotUser,
        UsercopyError::PageNotWritable,
        UsercopyError::PageFault,
        UsercopyError::NoProcessContext,
        UsercopyError::SizeTooLarge,
    ];

    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(format!("{}", variants[i]), format!("{}", variants[j]));
        }
    }
}

#[test]
fn test_usercopy_error_result_ok() {
    let result: Result<(), UsercopyError> = Ok(());
    assert!(result.is_ok());
}

#[test]
fn test_usercopy_error_result_err() {
    let result: Result<(), UsercopyError> = Err(UsercopyError::PageFault);
    assert!(result.is_err());
    assert_eq!(result.err(), Some(UsercopyError::PageFault));
}

#[test]
fn test_usercopy_error_match_exhaustive() {
    let err = UsercopyError::NullPointer;
    let matched = match err {
        UsercopyError::NullPointer => true,
        UsercopyError::InvalidAddress => false,
        UsercopyError::AddressOverflow => false,
        UsercopyError::PageNotMapped => false,
        UsercopyError::PageNotUser => false,
        UsercopyError::PageNotWritable => false,
        UsercopyError::PageFault => false,
        UsercopyError::NoProcessContext => false,
        UsercopyError::SizeTooLarge => false,
    };
    assert!(matched);
}
