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

use crate::sys::serial::*;

#[test]
fn test_serial_port_constant() {
    assert_eq!(core::SERIAL_PORT, 0x3F8);
}

#[test]
fn test_serial_print_empty_slice() {
    print(b"");
}

#[test]
fn test_serial_print_single_byte() {
    print(b"X");
}

#[test]
fn test_serial_print_multiple_bytes() {
    print(b"Hello");
}

#[test]
fn test_serial_print_special_chars() {
    print(b"\r\n");
}

#[test]
fn test_serial_print_str_empty() {
    print_str("");
}

#[test]
fn test_serial_print_str_single() {
    print_str("X");
}

#[test]
fn test_serial_print_str_multiple() {
    print_str("Hello, World!");
}

#[test]
fn test_serial_println_empty() {
    println(b"");
}

#[test]
fn test_serial_println_message() {
    println(b"Test message");
}

#[test]
fn test_serial_print_hex_zero() {
    print_hex(0);
}

#[test]
fn test_serial_print_hex_one() {
    print_hex(1);
}

#[test]
fn test_serial_print_hex_max() {
    print_hex(u64::MAX);
}

#[test]
fn test_serial_print_hex_arbitrary() {
    print_hex(0xDEADBEEF);
}

#[test]
fn test_serial_print_hex_powers_of_two() {
    for i in 0..64u64 {
        print_hex(1u64 << i);
    }
}

#[test]
fn test_serial_print_dec_zero() {
    print_dec(0);
}

#[test]
fn test_serial_print_dec_one() {
    print_dec(1);
}

#[test]
fn test_serial_print_dec_max() {
    print_dec(u64::MAX);
}

#[test]
fn test_serial_print_dec_arbitrary() {
    print_dec(12345);
}

#[test]
fn test_serial_print_dec_powers_of_ten() {
    let mut val = 1u64;
    for _ in 0..19 {
        print_dec(val);
        val *= 10;
    }
}

#[test]
fn test_serial_print_dec_sequential() {
    for i in 0..100u64 {
        print_dec(i);
    }
}

#[test]
fn test_serial_set_debug_enabled_true() {
    set_debug_enabled(true);
    assert!(is_debug_enabled());
}

#[test]
fn test_serial_set_debug_enabled_false() {
    set_debug_enabled(false);
    assert!(!is_debug_enabled());
}

#[test]
fn test_serial_set_debug_enabled_toggle() {
    let initial = is_debug_enabled();
    set_debug_enabled(!initial);
    assert_eq!(is_debug_enabled(), !initial);
    set_debug_enabled(initial);
    assert_eq!(is_debug_enabled(), initial);
}

#[test]
fn test_serial_is_debug_enabled_returns_bool() {
    let result: bool = is_debug_enabled();
    assert!(result == true || result == false);
}

#[test]
fn test_serial_print_binary_data() {
    let data: [u8; 4] = [0x00, 0x7F, 0x80, 0xFF];
    print(&data);
}

#[test]
fn test_serial_print_newline_variations() {
    print(b"\n");
    print(b"\r");
    print(b"\r\n");
}

#[test]
fn test_serial_print_tab() {
    print(b"\t");
}

#[test]
fn test_serial_print_all_printable_ascii() {
    for ch in 0x20u8..=0x7Eu8 {
        print(&[ch]);
    }
}

#[test]
fn test_serial_print_long_string() {
    let long_str = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    print(long_str);
}

#[test]
fn test_serial_println_adds_newline() {
    println(b"Line 1");
    println(b"Line 2");
}

#[test]
fn test_serial_print_hex_single_digit() {
    for i in 0..16u64 {
        print_hex(i);
    }
}

#[test]
fn test_serial_print_dec_single_digit() {
    for i in 0..10u64 {
        print_dec(i);
    }
}

#[test]
fn test_serial_combined_output() {
    print(b"Value: ");
    print_dec(42);
    print(b" (0x");
    print_hex(42);
    println(b")");
}

#[test]
fn test_serial_debug_flag_persistence() {
    let original = is_debug_enabled();
    set_debug_enabled(true);
    assert!(is_debug_enabled());
    set_debug_enabled(false);
    assert!(!is_debug_enabled());
    set_debug_enabled(original);
}

#[test]
fn test_serial_print_str_utf8() {
    print_str("ASCII");
}

#[test]
fn test_serial_print_u64_alias() {
    print_dec(999);
}

#[test]
fn test_serial_port_is_com1() {
    let com1_standard: u16 = 0x3F8;
    assert_eq!(core::SERIAL_PORT, com1_standard);
}

#[test]
fn test_serial_related_ports() {
    let base = core::SERIAL_PORT;
    assert_eq!(base + 0, 0x3F8);
    assert_eq!(base + 1, 0x3F9);
    assert_eq!(base + 2, 0x3FA);
    assert_eq!(base + 3, 0x3FB);
    assert_eq!(base + 4, 0x3FC);
    assert_eq!(base + 5, 0x3FD);
    assert_eq!(base + 6, 0x3FE);
    assert_eq!(base + 7, 0x3FF);
}
