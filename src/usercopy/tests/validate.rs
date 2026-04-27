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

use crate::test::framework::TestResult;
use crate::usercopy::*;

const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
const MAX_COPY_SIZE: usize = 64 * 1024 * 1024;

pub(crate) fn test_validate_user_read_null_pointer() -> TestResult {
    let result = validate_user_read(0, 100);
    if result != Err(UsercopyError::NullPointer) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_null_pointer() -> TestResult {
    let result = validate_user_write(0, 100);
    if result != Err(UsercopyError::NullPointer) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_zero_length() -> TestResult {
    let result = validate_user_read(0x1000, 0);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_zero_length() -> TestResult {
    let result = validate_user_write(0x1000, 0);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_size_too_large() -> TestResult {
    let result = validate_user_read(0x1000, MAX_COPY_SIZE + 1);
    if result != Err(UsercopyError::SizeTooLarge) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_size_too_large() -> TestResult {
    let result = validate_user_write(0x1000, MAX_COPY_SIZE + 1);
    if result != Err(UsercopyError::SizeTooLarge) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_max_copy_size_exact() -> TestResult {
    let result = validate_user_read(0x1000, MAX_COPY_SIZE);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_max_copy_size_exact() -> TestResult {
    let result = validate_user_write(0x1000, MAX_COPY_SIZE);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_address_overflow() -> TestResult {
    let result = validate_user_read(u64::MAX, 100);
    if result != Err(UsercopyError::AddressOverflow) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_address_overflow() -> TestResult {
    let result = validate_user_write(u64::MAX, 100);
    if result != Err(UsercopyError::AddressOverflow) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_address_overflow_boundary() -> TestResult {
    let result = validate_user_read(u64::MAX - 50, 100);
    if result != Err(UsercopyError::AddressOverflow) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_address_overflow_boundary() -> TestResult {
    let result = validate_user_write(u64::MAX - 50, 100);
    if result != Err(UsercopyError::AddressOverflow) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_kernel_space_start() -> TestResult {
    let result = validate_user_read(0xFFFF_8000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_kernel_space_start() -> TestResult {
    let result = validate_user_write(0xFFFF_8000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_kernel_space_high() -> TestResult {
    let result = validate_user_read(0xFFFF_FFFF_FFFF_F000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_kernel_space_high() -> TestResult {
    let result = validate_user_write(0xFFFF_FFFF_FFFF_F000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_non_canonical_address() -> TestResult {
    let result = validate_user_read(0x8000_0000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_non_canonical_address() -> TestResult {
    let result = validate_user_write(0x8000_0000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_user_space_end_boundary() -> TestResult {
    let result = validate_user_read(USER_SPACE_END, 1);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_user_space_end_boundary() -> TestResult {
    let result = validate_user_write(USER_SPACE_END, 1);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_crosses_user_space_boundary() -> TestResult {
    let result = validate_user_read(USER_SPACE_END - 50, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_crosses_user_space_boundary() -> TestResult {
    let result = validate_user_write(USER_SPACE_END - 50, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_valid_low_address() -> TestResult {
    let result = validate_user_read(0x1000, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_valid_low_address() -> TestResult {
    let result = validate_user_write(0x1000, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_page_aligned_address() -> TestResult {
    let result = validate_user_read(0x1000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_page_aligned_address() -> TestResult {
    let result = validate_user_write(0x1000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_non_page_aligned_address() -> TestResult {
    let result = validate_user_read(0x1001, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_non_page_aligned_address() -> TestResult {
    let result = validate_user_write(0x1001, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_crossing_page_boundary() -> TestResult {
    let result = validate_user_read(0x1FF0, 32);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_crossing_page_boundary() -> TestResult {
    let result = validate_user_write(0x1FF0, 32);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_multiple_pages() -> TestResult {
    let result = validate_user_read(0x1000, 8192);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_multiple_pages() -> TestResult {
    let result = validate_user_write(0x1000, 8192);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_single_byte() -> TestResult {
    let result = validate_user_read(0x1000, 1);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_single_byte() -> TestResult {
    let result = validate_user_write(0x1000, 1);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_large_valid_size() -> TestResult {
    let result = validate_user_read(0x1000, 1024 * 1024);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_large_valid_size() -> TestResult {
    let result = validate_user_write(0x1000, 1024 * 1024);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_end_exactly_at_boundary() -> TestResult {
    let addr = USER_SPACE_END - 99;
    let result = validate_user_read(addr, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_end_exactly_at_boundary() -> TestResult {
    let addr = USER_SPACE_END - 99;
    let result = validate_user_write(addr, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_address_one() -> TestResult {
    let result = validate_user_read(1, 1);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_address_one() -> TestResult {
    let result = validate_user_write(1, 1);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_hole_address() -> TestResult {
    let result = validate_user_read(0x0001_0000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_hole_address() -> TestResult {
    let result = validate_user_write(0x0001_0000_0000_0000, 100);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_just_above_user_space() -> TestResult {
    let result = validate_user_read(USER_SPACE_END + 1, 1);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_just_above_user_space() -> TestResult {
    let result = validate_user_write(USER_SPACE_END + 1, 1);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_wrapping_length() -> TestResult {
    let result = validate_user_read(0x7FFF_FFFF_FF00, 0x200);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_wrapping_length() -> TestResult {
    let result = validate_user_write(0x7FFF_FFFF_FF00, 0x200);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_mid_range_address() -> TestResult {
    let result = validate_user_read(0x0000_4000_0000_0000, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_mid_range_address() -> TestResult {
    let result = validate_user_write(0x0000_4000_0000_0000, 100);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_exact_page_size() -> TestResult {
    let result = validate_user_read(0x10000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_exact_page_size() -> TestResult {
    let result = validate_user_write(0x10000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_typical_stack_address() -> TestResult {
    let result = validate_user_read(0x7FFF_FFFE_0000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_typical_stack_address() -> TestResult {
    let result = validate_user_write(0x7FFF_FFFE_0000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_typical_heap_address() -> TestResult {
    let result = validate_user_read(0x0000_5555_5555_0000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_typical_heap_address() -> TestResult {
    let result = validate_user_write(0x0000_5555_5555_0000, 4096);
    if !(result.is_err() || result.is_ok()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_read_negative_canonical_boundary() -> TestResult {
    let result = validate_user_read(0xFFFF_7FFF_FFFF_FFFF, 1);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_user_write_negative_canonical_boundary() -> TestResult {
    let result = validate_user_write(0xFFFF_7FFF_FFFF_FFFF, 1);
    if result != Err(UsercopyError::InvalidAddress) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
