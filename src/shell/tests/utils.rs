// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::commands::utils::*;
use crate::test::framework::TestResult;

pub(crate) fn test_trim_bytes_empty() -> TestResult {
    if trim_bytes(b"") != b"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_no_spaces() -> TestResult {
    if trim_bytes(b"hello") != b"hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_leading_spaces() -> TestResult {
    if trim_bytes(b"   hello") != b"hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_trailing_spaces() -> TestResult {
    if trim_bytes(b"hello   ") != b"hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_both_sides() -> TestResult {
    if trim_bytes(b"  hello  ") != b"hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_only_spaces() -> TestResult {
    if trim_bytes(b"     ") != b"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_single_char() -> TestResult {
    if trim_bytes(b"x") != b"x" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_single_space_char() -> TestResult {
    if trim_bytes(b" x ") != b"x" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_internal_spaces() -> TestResult {
    if trim_bytes(b"hello world") != b"hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_bytes_multiple_internal_spaces() -> TestResult {
    if trim_bytes(b"hello   world") != b"hello   world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_true() -> TestResult {
    if !starts_with(b"hello world", b"hello") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_false() -> TestResult {
    if starts_with(b"hello world", b"world") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_exact() -> TestResult {
    if !starts_with(b"hello", b"hello") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_empty_prefix() -> TestResult {
    if !starts_with(b"hello", b"") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_empty_string() -> TestResult {
    if starts_with(b"", b"hello") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_longer_prefix() -> TestResult {
    if starts_with(b"hi", b"hello") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_starts_with_single_char() -> TestResult {
    if !starts_with(b"hello", b"h") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_bytes() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 500);
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].ends_with(b" B") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_kilobytes() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2048);
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].ends_with(b" KB") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_megabytes() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2 * 1024 * 1024);
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].ends_with(b" MB") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_gigabytes() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2 * 1024 * 1024 * 1024);
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].ends_with(b" GB") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_zero() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 0);
    if len <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_size_one() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 1);
    if len <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_unit_zero() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 0, 0, b" X");
    if &buf[..len] != b"0 X" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_unit_with_frac() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 10, 5, b" MB");
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].contains(&b'.') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_unit_large() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 12345, 0, b" KB");
    if len <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_decimal_zero() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 0);
    if &buf[..len] != b"0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_decimal_single() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 7);
    if &buf[..len] != b"7" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_decimal_large() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 123456789);
    if &buf[..len] != b"123456789" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_simple_zero() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 0);
    if &buf[..len] != b"0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_simple_positive() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 42);
    if &buf[..len] != b"42" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_num_simple_large() -> TestResult {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 9999);
    if &buf[..len] != b"9999" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_write_right_aligned() -> TestResult {
    let mut buf = [0u8; 32];
    let end = write_right_aligned(&mut buf, 0, 42, 5);
    if end <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_write_right_aligned_padding() -> TestResult {
    let mut buf = [0u8; 32];
    let end = write_right_aligned(&mut buf, 0, 5, 8);
    if buf[0..end].iter().filter(|&&c| c == b' ').count() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_write_size_col() -> TestResult {
    let mut buf = [0u8; 32];
    let len = write_size_col(&mut buf, 1024 * 1024);
    if len <= 0 {
        return TestResult::Fail;
    }
    if !buf[..len].contains(&b'M') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_write_size_col_large() -> TestResult {
    let mut buf = [0u8; 32];
    let len = write_size_col(&mut buf, 100 * 1024 * 1024);
    if len <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_hex_byte_zero() -> TestResult {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x00);
    if &buf != b"00" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_hex_byte_ff() -> TestResult {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0xFF);
    if &buf != b"FF" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_hex_byte_mid() -> TestResult {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x5A);
    if &buf != b"5A" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_hex_byte_low() -> TestResult {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x0F);
    if &buf != b"0F" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_hex_byte_high() -> TestResult {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0xF0);
    if &buf != b"F0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
