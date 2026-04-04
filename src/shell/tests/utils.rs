use crate::shell::commands::utils::*;

#[test]
fn test_trim_bytes_empty() {
    assert_eq!(trim_bytes(b""), b"");
}

#[test]
fn test_trim_bytes_no_spaces() {
    assert_eq!(trim_bytes(b"hello"), b"hello");
}

#[test]
fn test_trim_bytes_leading_spaces() {
    assert_eq!(trim_bytes(b"   hello"), b"hello");
}

#[test]
fn test_trim_bytes_trailing_spaces() {
    assert_eq!(trim_bytes(b"hello   "), b"hello");
}

#[test]
fn test_trim_bytes_both_sides() {
    assert_eq!(trim_bytes(b"  hello  "), b"hello");
}

#[test]
fn test_trim_bytes_only_spaces() {
    assert_eq!(trim_bytes(b"     "), b"");
}

#[test]
fn test_trim_bytes_single_char() {
    assert_eq!(trim_bytes(b"x"), b"x");
}

#[test]
fn test_trim_bytes_single_space_char() {
    assert_eq!(trim_bytes(b" x "), b"x");
}

#[test]
fn test_trim_bytes_internal_spaces() {
    assert_eq!(trim_bytes(b"hello world"), b"hello world");
}

#[test]
fn test_trim_bytes_multiple_internal_spaces() {
    assert_eq!(trim_bytes(b"hello   world"), b"hello   world");
}

#[test]
fn test_starts_with_true() {
    assert!(starts_with(b"hello world", b"hello"));
}

#[test]
fn test_starts_with_false() {
    assert!(!starts_with(b"hello world", b"world"));
}

#[test]
fn test_starts_with_exact() {
    assert!(starts_with(b"hello", b"hello"));
}

#[test]
fn test_starts_with_empty_prefix() {
    assert!(starts_with(b"hello", b""));
}

#[test]
fn test_starts_with_empty_string() {
    assert!(!starts_with(b"", b"hello"));
}

#[test]
fn test_starts_with_longer_prefix() {
    assert!(!starts_with(b"hi", b"hello"));
}

#[test]
fn test_starts_with_single_char() {
    assert!(starts_with(b"hello", b"h"));
}

#[test]
fn test_format_size_bytes() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 500);
    assert!(len > 0);
    assert!(buf[..len].ends_with(b" B"));
}

#[test]
fn test_format_size_kilobytes() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2048);
    assert!(len > 0);
    assert!(buf[..len].ends_with(b" KB"));
}

#[test]
fn test_format_size_megabytes() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2 * 1024 * 1024);
    assert!(len > 0);
    assert!(buf[..len].ends_with(b" MB"));
}

#[test]
fn test_format_size_gigabytes() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 2 * 1024 * 1024 * 1024);
    assert!(len > 0);
    assert!(buf[..len].ends_with(b" GB"));
}

#[test]
fn test_format_size_zero() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 0);
    assert!(len > 0);
}

#[test]
fn test_format_size_one() {
    let mut buf = [0u8; 32];
    let len = format_size(&mut buf, 1);
    assert!(len > 0);
}

#[test]
fn test_format_num_unit_zero() {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 0, 0, b" X");
    assert_eq!(&buf[..len], b"0 X");
}

#[test]
fn test_format_num_unit_with_frac() {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 10, 5, b" MB");
    assert!(len > 0);
    assert!(buf[..len].contains(&b'.'));
}

#[test]
fn test_format_num_unit_large() {
    let mut buf = [0u8; 32];
    let len = format_num_unit(&mut buf, 12345, 0, b" KB");
    assert!(len > 0);
}

#[test]
fn test_format_decimal_zero() {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 0);
    assert_eq!(&buf[..len], b"0");
}

#[test]
fn test_format_decimal_single() {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 7);
    assert_eq!(&buf[..len], b"7");
}

#[test]
fn test_format_decimal_large() {
    let mut buf = [0u8; 32];
    let len = format_decimal(&mut buf, 123456789);
    assert_eq!(&buf[..len], b"123456789");
}

#[test]
fn test_format_num_simple_zero() {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 0);
    assert_eq!(&buf[..len], b"0");
}

#[test]
fn test_format_num_simple_positive() {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 42);
    assert_eq!(&buf[..len], b"42");
}

#[test]
fn test_format_num_simple_large() {
    let mut buf = [0u8; 32];
    let len = format_num_simple(&mut buf, 9999);
    assert_eq!(&buf[..len], b"9999");
}

#[test]
fn test_write_right_aligned() {
    let mut buf = [0u8; 32];
    let end = write_right_aligned(&mut buf, 0, 42, 5);
    assert!(end > 0);
}

#[test]
fn test_write_right_aligned_padding() {
    let mut buf = [0u8; 32];
    let end = write_right_aligned(&mut buf, 0, 5, 8);
    assert!(buf[0..end].iter().filter(|&&c| c == b' ').count() > 0);
}

#[test]
fn test_write_size_col() {
    let mut buf = [0u8; 32];
    let len = write_size_col(&mut buf, 1024 * 1024);
    assert!(len > 0);
    assert!(buf[..len].contains(&b'M'));
}

#[test]
fn test_write_size_col_large() {
    let mut buf = [0u8; 32];
    let len = write_size_col(&mut buf, 100 * 1024 * 1024);
    assert!(len > 0);
}

#[test]
fn test_format_hex_byte_zero() {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x00);
    assert_eq!(&buf, b"00");
}

#[test]
fn test_format_hex_byte_ff() {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0xFF);
    assert_eq!(&buf, b"FF");
}

#[test]
fn test_format_hex_byte_mid() {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x5A);
    assert_eq!(&buf, b"5A");
}

#[test]
fn test_format_hex_byte_low() {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0x0F);
    assert_eq!(&buf, b"0F");
}

#[test]
fn test_format_hex_byte_high() {
    let mut buf = [0u8; 2];
    format_hex_byte(&mut buf, 0xF0);
    assert_eq!(&buf, b"F0");
}
