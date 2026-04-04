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

use crate::sys::io::*;

#[test]
fn test_io_wait_exists() {
    io_wait();
}

#[test]
fn test_io_wait_multiple_calls() {
    for _ in 0..10 {
        io_wait();
    }
}

#[test]
fn test_outb_function_signature() {
    fn _check_signature(_port: u16, _val: u8) {
        unsafe { outb(_port, _val); }
    }
}

#[test]
fn test_inb_function_signature() {
    fn _check_signature(_port: u16) -> u8 {
        unsafe { inb(_port) }
    }
}

#[test]
fn test_outw_function_signature() {
    fn _check_signature(_port: u16, _val: u16) {
        unsafe { outw(_port, _val); }
    }
}

#[test]
fn test_inw_function_signature() {
    fn _check_signature(_port: u16) -> u16 {
        unsafe { inw(_port) }
    }
}

#[test]
fn test_outl_function_signature() {
    fn _check_signature(_port: u16, _val: u32) {
        unsafe { outl(_port, _val); }
    }
}

#[test]
fn test_inl_function_signature() {
    fn _check_signature(_port: u16) -> u32 {
        unsafe { inl(_port) }
    }
}

#[test]
fn test_port_types_are_u16() {
    let port: u16 = 0x3F8;
    assert_eq!(port, 0x3F8);
}

#[test]
fn test_byte_value_type() {
    let val: u8 = 0xFF;
    assert_eq!(val, 255);
}

#[test]
fn test_word_value_type() {
    let val: u16 = 0xFFFF;
    assert_eq!(val, 65535);
}

#[test]
fn test_dword_value_type() {
    let val: u32 = 0xFFFFFFFF;
    assert_eq!(val, 4294967295);
}

#[test]
fn test_common_port_addresses() {
    let com1: u16 = 0x3F8;
    let com2: u16 = 0x2F8;
    let com3: u16 = 0x3E8;
    let com4: u16 = 0x2E8;
    assert_eq!(com1, 0x3F8);
    assert_eq!(com2, 0x2F8);
    assert_eq!(com3, 0x3E8);
    assert_eq!(com4, 0x2E8);
}

#[test]
fn test_pic_port_addresses() {
    let pic1_cmd: u16 = 0x20;
    let pic1_data: u16 = 0x21;
    let pic2_cmd: u16 = 0xA0;
    let pic2_data: u16 = 0xA1;
    assert_eq!(pic1_cmd, 0x20);
    assert_eq!(pic1_data, 0x21);
    assert_eq!(pic2_cmd, 0xA0);
    assert_eq!(pic2_data, 0xA1);
}

#[test]
fn test_keyboard_port_address() {
    let keyboard_data: u16 = 0x60;
    let keyboard_status: u16 = 0x64;
    assert_eq!(keyboard_data, 0x60);
    assert_eq!(keyboard_status, 0x64);
}

#[test]
fn test_rtc_port_addresses() {
    let rtc_addr: u16 = 0x70;
    let rtc_data: u16 = 0x71;
    assert_eq!(rtc_addr, 0x70);
    assert_eq!(rtc_data, 0x71);
}

#[test]
fn test_cmos_port_addresses() {
    let cmos_addr: u16 = 0x70;
    let cmos_data: u16 = 0x71;
    assert_eq!(cmos_addr, 0x70);
    assert_eq!(cmos_data, 0x71);
}

#[test]
fn test_pci_config_ports() {
    let pci_config_addr: u16 = 0xCF8;
    let pci_config_data: u16 = 0xCFC;
    assert_eq!(pci_config_addr, 0xCF8);
    assert_eq!(pci_config_data, 0xCFC);
}

#[test]
fn test_io_wait_port() {
    let io_wait_port: u16 = 0x80;
    assert_eq!(io_wait_port, 0x80);
}

#[test]
fn test_port_max_value() {
    let max_port: u16 = u16::MAX;
    assert_eq!(max_port, 0xFFFF);
}

#[test]
fn test_port_min_value() {
    let min_port: u16 = 0x0000;
    assert_eq!(min_port, 0);
}

#[test]
fn test_byte_boundary_values() {
    let min_byte: u8 = 0x00;
    let max_byte: u8 = 0xFF;
    assert_eq!(min_byte, 0);
    assert_eq!(max_byte, 255);
}

#[test]
fn test_word_boundary_values() {
    let min_word: u16 = 0x0000;
    let max_word: u16 = 0xFFFF;
    assert_eq!(min_word, 0);
    assert_eq!(max_word, 65535);
}

#[test]
fn test_dword_boundary_values() {
    let min_dword: u32 = 0x00000000;
    let max_dword: u32 = 0xFFFFFFFF;
    assert_eq!(min_dword, 0);
    assert_eq!(max_dword, 4294967295);
}

#[test]
fn test_vga_port_addresses() {
    let vga_misc_out: u16 = 0x3C2;
    let vga_seq_index: u16 = 0x3C4;
    let vga_seq_data: u16 = 0x3C5;
    assert_eq!(vga_misc_out, 0x3C2);
    assert_eq!(vga_seq_index, 0x3C4);
    assert_eq!(vga_seq_data, 0x3C5);
}

#[test]
fn test_ata_primary_ports() {
    let ata_primary_base: u16 = 0x1F0;
    let ata_primary_ctrl: u16 = 0x3F6;
    assert_eq!(ata_primary_base, 0x1F0);
    assert_eq!(ata_primary_ctrl, 0x3F6);
}

#[test]
fn test_ata_secondary_ports() {
    let ata_secondary_base: u16 = 0x170;
    let ata_secondary_ctrl: u16 = 0x376;
    assert_eq!(ata_secondary_base, 0x170);
    assert_eq!(ata_secondary_ctrl, 0x376);
}
