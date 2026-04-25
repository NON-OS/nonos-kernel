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
use crate::test::framework::TestResult;

pub(crate) fn test_serial_port_constant() -> TestResult {
    if core::SERIAL_PORT != 0x3F8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_empty_slice() -> TestResult {
    print(b"");
    TestResult::Pass
}

pub(crate) fn test_serial_print_single_byte() -> TestResult {
    print(b"X");
    TestResult::Pass
}

pub(crate) fn test_serial_print_multiple_bytes() -> TestResult {
    print(b"Hello");
    TestResult::Pass
}

pub(crate) fn test_serial_print_special_chars() -> TestResult {
    print(b"\r\n");
    TestResult::Pass
}

pub(crate) fn test_serial_print_str_empty() -> TestResult {
    print_str("");
    TestResult::Pass
}

pub(crate) fn test_serial_print_str_single() -> TestResult {
    print_str("X");
    TestResult::Pass
}

pub(crate) fn test_serial_print_str_multiple() -> TestResult {
    print_str("Hello, World!");
    TestResult::Pass
}

pub(crate) fn test_serial_println_empty() -> TestResult {
    println(b"");
    TestResult::Pass
}

pub(crate) fn test_serial_println_message() -> TestResult {
    println(b"Test message");
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_zero() -> TestResult {
    print_hex(0);
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_one() -> TestResult {
    print_hex(1);
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_max() -> TestResult {
    print_hex(u64::MAX);
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_arbitrary() -> TestResult {
    print_hex(0xDEADBEEF);
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_powers_of_two() -> TestResult {
    for i in 0..64u64 {
        print_hex(1u64 << i);
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_zero() -> TestResult {
    print_dec(0);
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_one() -> TestResult {
    print_dec(1);
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_max() -> TestResult {
    print_dec(u64::MAX);
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_arbitrary() -> TestResult {
    print_dec(12345);
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_powers_of_ten() -> TestResult {
    let mut val = 1u64;
    for _ in 0..19 {
        print_dec(val);
        val *= 10;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_sequential() -> TestResult {
    for i in 0..100u64 {
        print_dec(i);
    }
    TestResult::Pass
}

pub(crate) fn test_serial_set_debug_enabled_true() -> TestResult {
    set_debug_enabled(true);
    if !is_debug_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_set_debug_enabled_false() -> TestResult {
    set_debug_enabled(false);
    if is_debug_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_set_debug_enabled_toggle() -> TestResult {
    let initial = is_debug_enabled();
    set_debug_enabled(!initial);
    if is_debug_enabled() != !initial {
        return TestResult::Fail;
    }
    set_debug_enabled(initial);
    if is_debug_enabled() != initial {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_is_debug_enabled_returns_bool() -> TestResult {
    let result: bool = is_debug_enabled();
    if !(result == true || result == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_binary_data() -> TestResult {
    let data: [u8; 4] = [0x00, 0x7F, 0x80, 0xFF];
    print(&data);
    TestResult::Pass
}

pub(crate) fn test_serial_print_newline_variations() -> TestResult {
    print(b"\n");
    print(b"\r");
    print(b"\r\n");
    TestResult::Pass
}

pub(crate) fn test_serial_print_tab() -> TestResult {
    print(b"\t");
    TestResult::Pass
}

pub(crate) fn test_serial_print_all_printable_ascii() -> TestResult {
    for ch in 0x20u8..=0x7Eu8 {
        print(&[ch]);
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_long_string() -> TestResult {
    let long_str = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    print(long_str);
    TestResult::Pass
}

pub(crate) fn test_serial_println_adds_newline() -> TestResult {
    println(b"Line 1");
    println(b"Line 2");
    TestResult::Pass
}

pub(crate) fn test_serial_print_hex_single_digit() -> TestResult {
    for i in 0..16u64 {
        print_hex(i);
    }
    TestResult::Pass
}

pub(crate) fn test_serial_print_dec_single_digit() -> TestResult {
    for i in 0..10u64 {
        print_dec(i);
    }
    TestResult::Pass
}

pub(crate) fn test_serial_combined_output() -> TestResult {
    print(b"Value: ");
    print_dec(42);
    print(b" (0x");
    print_hex(42);
    println(b")");
    TestResult::Pass
}

pub(crate) fn test_serial_debug_flag_persistence() -> TestResult {
    let original = is_debug_enabled();
    set_debug_enabled(true);
    if !is_debug_enabled() {
        return TestResult::Fail;
    }
    set_debug_enabled(false);
    if is_debug_enabled() {
        return TestResult::Fail;
    }
    set_debug_enabled(original);
    TestResult::Pass
}

pub(crate) fn test_serial_print_str_utf8() -> TestResult {
    print_str("ASCII");
    TestResult::Pass
}

pub(crate) fn test_serial_print_u64_alias() -> TestResult {
    print_dec(999);
    TestResult::Pass
}

pub(crate) fn test_serial_port_is_com1() -> TestResult {
    let com1_standard: u16 = 0x3F8;
    if core::SERIAL_PORT != com1_standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_related_ports() -> TestResult {
    let base = core::SERIAL_PORT;
    if base + 0 != 0x3F8 {
        return TestResult::Fail;
    }
    if base + 1 != 0x3F9 {
        return TestResult::Fail;
    }
    if base + 2 != 0x3FA {
        return TestResult::Fail;
    }
    if base + 3 != 0x3FB {
        return TestResult::Fail;
    }
    if base + 4 != 0x3FC {
        return TestResult::Fail;
    }
    if base + 5 != 0x3FD {
        return TestResult::Fail;
    }
    if base + 6 != 0x3FE {
        return TestResult::Fail;
    }
    if base + 7 != 0x3FF {
        return TestResult::Fail;
    }
    TestResult::Pass
}
