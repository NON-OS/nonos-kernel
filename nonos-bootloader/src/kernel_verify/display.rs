// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;
use uefi::CStr16;

#[inline]
pub fn mini_delay() {
}

#[inline]
pub fn print(st: &mut SystemTable<Boot>, s: &CStr16) {
    let _ = st.stdout().output_string(s);
}

pub fn print_hex_bytes(st: &mut SystemTable<Boot>, data: &[u8]) {
    for &b in data {
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        print_hex_digit(st, hi);
        print_hex_digit(st, lo);
    }
}

fn print_hex_digit(st: &mut SystemTable<Boot>, n: u8) {
    use uefi::cstr16;
    match n {
        0 => print(st, cstr16!("0")),
        1 => print(st, cstr16!("1")),
        2 => print(st, cstr16!("2")),
        3 => print(st, cstr16!("3")),
        4 => print(st, cstr16!("4")),
        5 => print(st, cstr16!("5")),
        6 => print(st, cstr16!("6")),
        7 => print(st, cstr16!("7")),
        8 => print(st, cstr16!("8")),
        9 => print(st, cstr16!("9")),
        10 => print(st, cstr16!("a")),
        11 => print(st, cstr16!("b")),
        12 => print(st, cstr16!("c")),
        13 => print(st, cstr16!("d")),
        14 => print(st, cstr16!("e")),
        15 => print(st, cstr16!("f")),
        _ => {}
    }
}

#[inline]
pub fn print_hex_char(st: &mut SystemTable<Boot>, n: u8) {
    print_hex_digit(st, n);
}

pub fn byte_to_hex(b: u8) -> [u8; 2] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [HEX[(b >> 4) as usize], HEX[(b & 0xF) as usize]]
}

pub fn print_kernel_size(_st: &mut SystemTable<Boot>, _size: usize) {
    // Output handled by main.rs
}

pub fn print_verification_success(_st: &mut SystemTable<Boot>) {
    // Output handled by main.rs
}

pub fn print_verification_failure(_st: &mut SystemTable<Boot>) {
    // Output handled by main.rs
}
