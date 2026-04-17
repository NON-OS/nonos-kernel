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
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_usercopy_error_null_pointer_variant() -> TestResult {
    let err = UsercopyError::NullPointer;
    if err != UsercopyError::NullPointer { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_invalid_address_variant() -> TestResult {
    let err = UsercopyError::InvalidAddress;
    if err != UsercopyError::InvalidAddress { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_address_overflow_variant() -> TestResult {
    let err = UsercopyError::AddressOverflow;
    if err != UsercopyError::AddressOverflow { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_page_not_mapped_variant() -> TestResult {
    let err = UsercopyError::PageNotMapped;
    if err != UsercopyError::PageNotMapped { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_page_not_user_variant() -> TestResult {
    let err = UsercopyError::PageNotUser;
    if err != UsercopyError::PageNotUser { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_page_not_writable_variant() -> TestResult {
    let err = UsercopyError::PageNotWritable;
    if err != UsercopyError::PageNotWritable { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_page_fault_variant() -> TestResult {
    let err = UsercopyError::PageFault;
    if err != UsercopyError::PageFault { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_no_process_context_variant() -> TestResult {
    let err = UsercopyError::NoProcessContext;
    if err != UsercopyError::NoProcessContext { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_size_too_large_variant() -> TestResult {
    let err = UsercopyError::SizeTooLarge;
    if err != UsercopyError::SizeTooLarge { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_variants_not_equal() -> TestResult {
    if UsercopyError::NullPointer == UsercopyError::InvalidAddress { return TestResult::Fail; }
    if UsercopyError::AddressOverflow == UsercopyError::PageNotMapped { return TestResult::Fail; }
    if UsercopyError::PageNotUser == UsercopyError::PageNotWritable { return TestResult::Fail; }
    if UsercopyError::PageFault == UsercopyError::NoProcessContext { return TestResult::Fail; }
    if UsercopyError::SizeTooLarge == UsercopyError::NullPointer { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_clone() -> TestResult {
    let err = UsercopyError::PageFault;
    let cloned = err.clone();
    if err != cloned { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_copy() -> TestResult {
    let err = UsercopyError::InvalidAddress;
    let copied = err;
    if err != copied { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_null_pointer() -> TestResult {
    let err = UsercopyError::NullPointer;
    if format!("{}", err) != "null pointer" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_invalid_address() -> TestResult {
    let err = UsercopyError::InvalidAddress;
    if format!("{}", err) != "invalid user address" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_address_overflow() -> TestResult {
    let err = UsercopyError::AddressOverflow;
    if format!("{}", err) != "address overflow" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_page_not_mapped() -> TestResult {
    let err = UsercopyError::PageNotMapped;
    if format!("{}", err) != "page not mapped" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_page_not_user() -> TestResult {
    let err = UsercopyError::PageNotUser;
    if format!("{}", err) != "page not accessible from userspace" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_page_not_writable() -> TestResult {
    let err = UsercopyError::PageNotWritable;
    if format!("{}", err) != "page not writable" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_page_fault() -> TestResult {
    let err = UsercopyError::PageFault;
    if format!("{}", err) != "page fault during access" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_no_process_context() -> TestResult {
    let err = UsercopyError::NoProcessContext;
    if format!("{}", err) != "no process context" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_display_size_too_large() -> TestResult {
    let err = UsercopyError::SizeTooLarge;
    if format!("{}", err) != "copy size too large" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_null_pointer() -> TestResult {
    let err = UsercopyError::NullPointer;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("NullPointer") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_invalid_address() -> TestResult {
    let err = UsercopyError::InvalidAddress;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("InvalidAddress") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_address_overflow() -> TestResult {
    let err = UsercopyError::AddressOverflow;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("AddressOverflow") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_page_not_mapped() -> TestResult {
    let err = UsercopyError::PageNotMapped;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("PageNotMapped") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_page_not_user() -> TestResult {
    let err = UsercopyError::PageNotUser;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("PageNotUser") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_page_not_writable() -> TestResult {
    let err = UsercopyError::PageNotWritable;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("PageNotWritable") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_page_fault() -> TestResult {
    let err = UsercopyError::PageFault;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("PageFault") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_no_process_context() -> TestResult {
    let err = UsercopyError::NoProcessContext;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("NoProcessContext") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_debug_size_too_large() -> TestResult {
    let err = UsercopyError::SizeTooLarge;
    let debug_str = format!("{:?}", err);
    if !debug_str.contains("SizeTooLarge") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_equality_same_variant() -> TestResult {
    if UsercopyError::NullPointer != UsercopyError::NullPointer { return TestResult::Fail; }
    if UsercopyError::InvalidAddress != UsercopyError::InvalidAddress { return TestResult::Fail; }
    if UsercopyError::AddressOverflow != UsercopyError::AddressOverflow { return TestResult::Fail; }
    if UsercopyError::PageNotMapped != UsercopyError::PageNotMapped { return TestResult::Fail; }
    if UsercopyError::PageNotUser != UsercopyError::PageNotUser { return TestResult::Fail; }
    if UsercopyError::PageNotWritable != UsercopyError::PageNotWritable { return TestResult::Fail; }
    if UsercopyError::PageFault != UsercopyError::PageFault { return TestResult::Fail; }
    if UsercopyError::NoProcessContext != UsercopyError::NoProcessContext { return TestResult::Fail; }
    if UsercopyError::SizeTooLarge != UsercopyError::SizeTooLarge { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_all_variants_unique_display() -> TestResult {
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
            if format!("{}", variants[i]) == format!("{}", variants[j]) { return TestResult::Fail; }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_result_ok() -> TestResult {
    let result: Result<(), UsercopyError> = Ok(());
    if !result.is_ok() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_result_err() -> TestResult {
    let result: Result<(), UsercopyError> = Err(UsercopyError::PageFault);
    if !result.is_err() { return TestResult::Fail; }
    if result.err() != Some(UsercopyError::PageFault) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_usercopy_error_match_exhaustive() -> TestResult {
    let err = UsercopyError::NullPointer;
    let matched = match err {
        UsercopyError::NullPointer => true,
        UsercopyError::InvalidAddress => false,
        UsercopyError::AddressOverflow => false,
        UsercopyError::MisalignedAddress => false,
        UsercopyError::PageNotMapped => false,
        UsercopyError::PageNotUser => false,
        UsercopyError::PageNotWritable => false,
        UsercopyError::PageFault => false,
        UsercopyError::NoProcessContext => false,
        UsercopyError::SizeTooLarge => false,
        UsercopyError::InvalidUtf8 => false,
    };
    if !matched { return TestResult::Fail; }
    TestResult::Pass
}
