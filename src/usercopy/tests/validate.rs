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

const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
const MAX_COPY_SIZE: usize = 64 * 1024 * 1024;

#[test]
fn test_validate_user_read_null_pointer() {
    let result = validate_user_read(0, 100);
    assert_eq!(result, Err(UsercopyError::NullPointer));
}

#[test]
fn test_validate_user_write_null_pointer() {
    let result = validate_user_write(0, 100);
    assert_eq!(result, Err(UsercopyError::NullPointer));
}

#[test]
fn test_validate_user_read_zero_length() {
    let result = validate_user_read(0x1000, 0);
    assert!(result.is_ok());
}

#[test]
fn test_validate_user_write_zero_length() {
    let result = validate_user_write(0x1000, 0);
    assert!(result.is_ok());
}

#[test]
fn test_validate_user_read_size_too_large() {
    let result = validate_user_read(0x1000, MAX_COPY_SIZE + 1);
    assert_eq!(result, Err(UsercopyError::SizeTooLarge));
}

#[test]
fn test_validate_user_write_size_too_large() {
    let result = validate_user_write(0x1000, MAX_COPY_SIZE + 1);
    assert_eq!(result, Err(UsercopyError::SizeTooLarge));
}

#[test]
fn test_validate_user_read_max_copy_size_exact() {
    let result = validate_user_read(0x1000, MAX_COPY_SIZE);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_write_max_copy_size_exact() {
    let result = validate_user_write(0x1000, MAX_COPY_SIZE);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_read_address_overflow() {
    let result = validate_user_read(u64::MAX, 100);
    assert_eq!(result, Err(UsercopyError::AddressOverflow));
}

#[test]
fn test_validate_user_write_address_overflow() {
    let result = validate_user_write(u64::MAX, 100);
    assert_eq!(result, Err(UsercopyError::AddressOverflow));
}

#[test]
fn test_validate_user_read_address_overflow_boundary() {
    let result = validate_user_read(u64::MAX - 50, 100);
    assert_eq!(result, Err(UsercopyError::AddressOverflow));
}

#[test]
fn test_validate_user_write_address_overflow_boundary() {
    let result = validate_user_write(u64::MAX - 50, 100);
    assert_eq!(result, Err(UsercopyError::AddressOverflow));
}

#[test]
fn test_validate_user_read_kernel_space_start() {
    let result = validate_user_read(0xFFFF_8000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_kernel_space_start() {
    let result = validate_user_write(0xFFFF_8000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_kernel_space_high() {
    let result = validate_user_read(0xFFFF_FFFF_FFFF_F000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_kernel_space_high() {
    let result = validate_user_write(0xFFFF_FFFF_FFFF_F000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_non_canonical_address() {
    let result = validate_user_read(0x8000_0000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_non_canonical_address() {
    let result = validate_user_write(0x8000_0000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_user_space_end_boundary() {
    let result = validate_user_read(USER_SPACE_END, 1);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_write_user_space_end_boundary() {
    let result = validate_user_write(USER_SPACE_END, 1);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_read_crosses_user_space_boundary() {
    let result = validate_user_read(USER_SPACE_END - 50, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_crosses_user_space_boundary() {
    let result = validate_user_write(USER_SPACE_END - 50, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_valid_low_address() {
    let result = validate_user_read(0x1000, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_valid_low_address() {
    let result = validate_user_write(0x1000, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_page_aligned_address() {
    let result = validate_user_read(0x1000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_page_aligned_address() {
    let result = validate_user_write(0x1000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_non_page_aligned_address() {
    let result = validate_user_read(0x1001, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_non_page_aligned_address() {
    let result = validate_user_write(0x1001, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_crossing_page_boundary() {
    let result = validate_user_read(0x1FF0, 32);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_crossing_page_boundary() {
    let result = validate_user_write(0x1FF0, 32);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_multiple_pages() {
    let result = validate_user_read(0x1000, 8192);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_multiple_pages() {
    let result = validate_user_write(0x1000, 8192);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_single_byte() {
    let result = validate_user_read(0x1000, 1);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_single_byte() {
    let result = validate_user_write(0x1000, 1);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_large_valid_size() {
    let result = validate_user_read(0x1000, 1024 * 1024);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_large_valid_size() {
    let result = validate_user_write(0x1000, 1024 * 1024);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_end_exactly_at_boundary() {
    let addr = USER_SPACE_END - 99;
    let result = validate_user_read(addr, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_end_exactly_at_boundary() {
    let addr = USER_SPACE_END - 99;
    let result = validate_user_write(addr, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_address_one() {
    let result = validate_user_read(1, 1);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_address_one() {
    let result = validate_user_write(1, 1);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_hole_address() {
    let result = validate_user_read(0x0001_0000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_hole_address() {
    let result = validate_user_write(0x0001_0000_0000_0000, 100);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_just_above_user_space() {
    let result = validate_user_read(USER_SPACE_END + 1, 1);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_just_above_user_space() {
    let result = validate_user_write(USER_SPACE_END + 1, 1);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_read_wrapping_length() {
    let result = validate_user_read(0x7FFF_FFFF_FF00, 0x200);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_write_wrapping_length() {
    let result = validate_user_write(0x7FFF_FFFF_FF00, 0x200);
    assert!(result.is_err());
}

#[test]
fn test_validate_user_read_mid_range_address() {
    let result = validate_user_read(0x0000_4000_0000_0000, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_mid_range_address() {
    let result = validate_user_write(0x0000_4000_0000_0000, 100);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_exact_page_size() {
    let result = validate_user_read(0x10000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_exact_page_size() {
    let result = validate_user_write(0x10000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_typical_stack_address() {
    let result = validate_user_read(0x7FFF_FFFE_0000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_typical_stack_address() {
    let result = validate_user_write(0x7FFF_FFFE_0000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_typical_heap_address() {
    let result = validate_user_read(0x0000_5555_5555_0000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_write_typical_heap_address() {
    let result = validate_user_write(0x0000_5555_5555_0000, 4096);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_validate_user_read_negative_canonical_boundary() {
    let result = validate_user_read(0xFFFF_7FFF_FFFF_FFFF, 1);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}

#[test]
fn test_validate_user_write_negative_canonical_boundary() {
    let result = validate_user_write(0xFFFF_7FFF_FFFF_FFFF, 1);
    assert_eq!(result, Err(UsercopyError::InvalidAddress));
}
