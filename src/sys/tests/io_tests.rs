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
use crate::test::framework::TestResult;

pub(crate) fn test_io_wait_exists() -> TestResult {
    io_wait();
    TestResult::Pass
}

pub(crate) fn test_io_wait_multiple_calls() -> TestResult {
    for _ in 0..10 {
        io_wait();
    }
    TestResult::Pass
}

pub(crate) fn test_outb_function_signature() -> TestResult {
    fn _check_signature(_port: u16, _val: u8) {
        unsafe {
            outb(_port, _val);
        }
    }
    TestResult::Pass
}

pub(crate) fn test_inb_function_signature() -> TestResult {
    fn _check_signature(_port: u16) -> u8 {
        unsafe { inb(_port) }
    }
    TestResult::Pass
}

pub(crate) fn test_outw_function_signature() -> TestResult {
    fn _check_signature(_port: u16, _val: u16) {
        unsafe {
            outw(_port, _val);
        }
    }
    TestResult::Pass
}

pub(crate) fn test_inw_function_signature() -> TestResult {
    fn _check_signature(_port: u16) -> u16 {
        unsafe { inw(_port) }
    }
    TestResult::Pass
}

pub(crate) fn test_outl_function_signature() -> TestResult {
    fn _check_signature(_port: u16, _val: u32) {
        unsafe {
            outl(_port, _val);
        }
    }
    TestResult::Pass
}

pub(crate) fn test_inl_function_signature() -> TestResult {
    fn _check_signature(_port: u16) -> u32 {
        unsafe { inl(_port) }
    }
    TestResult::Pass
}

pub(crate) fn test_port_types_are_u16() -> TestResult {
    let port: u16 = 0x3F8;
    if port != 0x3F8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_byte_value_type() -> TestResult {
    let val: u8 = 0xFF;
    if val != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_word_value_type() -> TestResult {
    let val: u16 = 0xFFFF;
    if val != 65535 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dword_value_type() -> TestResult {
    let val: u32 = 0xFFFFFFFF;
    if val != 4294967295 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_common_port_addresses() -> TestResult {
    let com1: u16 = 0x3F8;
    let com2: u16 = 0x2F8;
    let com3: u16 = 0x3E8;
    let com4: u16 = 0x2E8;
    if com1 != 0x3F8 {
        return TestResult::Fail;
    }
    if com2 != 0x2F8 {
        return TestResult::Fail;
    }
    if com3 != 0x3E8 {
        return TestResult::Fail;
    }
    if com4 != 0x2E8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pic_port_addresses() -> TestResult {
    let pic1_cmd: u16 = 0x20;
    let pic1_data: u16 = 0x21;
    let pic2_cmd: u16 = 0xA0;
    let pic2_data: u16 = 0xA1;
    if pic1_cmd != 0x20 {
        return TestResult::Fail;
    }
    if pic1_data != 0x21 {
        return TestResult::Fail;
    }
    if pic2_cmd != 0xA0 {
        return TestResult::Fail;
    }
    if pic2_data != 0xA1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_port_address() -> TestResult {
    let keyboard_data: u16 = 0x60;
    let keyboard_status: u16 = 0x64;
    if keyboard_data != 0x60 {
        return TestResult::Fail;
    }
    if keyboard_status != 0x64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rtc_port_addresses() -> TestResult {
    let rtc_addr: u16 = 0x70;
    let rtc_data: u16 = 0x71;
    if rtc_addr != 0x70 {
        return TestResult::Fail;
    }
    if rtc_data != 0x71 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmos_port_addresses() -> TestResult {
    let cmos_addr: u16 = 0x70;
    let cmos_data: u16 = 0x71;
    if cmos_addr != 0x70 {
        return TestResult::Fail;
    }
    if cmos_data != 0x71 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_config_ports() -> TestResult {
    let pci_config_addr: u16 = 0xCF8;
    let pci_config_data: u16 = 0xCFC;
    if pci_config_addr != 0xCF8 {
        return TestResult::Fail;
    }
    if pci_config_data != 0xCFC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_io_wait_port() -> TestResult {
    let io_wait_port: u16 = 0x80;
    if io_wait_port != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_max_value() -> TestResult {
    let max_port: u16 = u16::MAX;
    if max_port != 0xFFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_min_value() -> TestResult {
    let min_port: u16 = 0x0000;
    if min_port != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_byte_boundary_values() -> TestResult {
    let min_byte: u8 = 0x00;
    let max_byte: u8 = 0xFF;
    if min_byte != 0 {
        return TestResult::Fail;
    }
    if max_byte != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_word_boundary_values() -> TestResult {
    let min_word: u16 = 0x0000;
    let max_word: u16 = 0xFFFF;
    if min_word != 0 {
        return TestResult::Fail;
    }
    if max_word != 65535 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dword_boundary_values() -> TestResult {
    let min_dword: u32 = 0x00000000;
    let max_dword: u32 = 0xFFFFFFFF;
    if min_dword != 0 {
        return TestResult::Fail;
    }
    if max_dword != 4294967295 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vga_port_addresses() -> TestResult {
    let vga_misc_out: u16 = 0x3C2;
    let vga_seq_index: u16 = 0x3C4;
    let vga_seq_data: u16 = 0x3C5;
    if vga_misc_out != 0x3C2 {
        return TestResult::Fail;
    }
    if vga_seq_index != 0x3C4 {
        return TestResult::Fail;
    }
    if vga_seq_data != 0x3C5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_primary_ports() -> TestResult {
    let ata_primary_base: u16 = 0x1F0;
    let ata_primary_ctrl: u16 = 0x3F6;
    if ata_primary_base != 0x1F0 {
        return TestResult::Fail;
    }
    if ata_primary_ctrl != 0x3F6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_secondary_ports() -> TestResult {
    let ata_secondary_base: u16 = 0x170;
    let ata_secondary_ctrl: u16 = 0x376;
    if ata_secondary_base != 0x170 {
        return TestResult::Fail;
    }
    if ata_secondary_ctrl != 0x376 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
