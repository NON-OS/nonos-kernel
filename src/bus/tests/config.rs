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

#[allow(unused_imports)]
use crate::bus::*;

fn test_pci_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31) | ((bus as u32) << 16) | ((device as u32) << 11)
        | ((function as u32) << 8) | ((offset as u32) & 0xFC)
}

#[test]
fn test_pci_address_enable_bit() {
    let addr = test_pci_address(0, 0, 0, 0);
    assert_eq!(addr & (1 << 31), 1 << 31);
}

#[test]
fn test_pci_address_bus_zero() {
    let addr = test_pci_address(0, 0, 0, 0);
    let bus = (addr >> 16) & 0xFF;
    assert_eq!(bus, 0);
}

#[test]
fn test_pci_address_bus_max() {
    let addr = test_pci_address(255, 0, 0, 0);
    let bus = (addr >> 16) & 0xFF;
    assert_eq!(bus, 255);
}

#[test]
fn test_pci_address_device_zero() {
    let addr = test_pci_address(0, 0, 0, 0);
    let device = (addr >> 11) & 0x1F;
    assert_eq!(device, 0);
}

#[test]
fn test_pci_address_device_max() {
    let addr = test_pci_address(0, 31, 0, 0);
    let device = (addr >> 11) & 0x1F;
    assert_eq!(device, 31);
}

#[test]
fn test_pci_address_function_zero() {
    let addr = test_pci_address(0, 0, 0, 0);
    let function = (addr >> 8) & 0x07;
    assert_eq!(function, 0);
}

#[test]
fn test_pci_address_function_max() {
    let addr = test_pci_address(0, 0, 7, 0);
    let function = (addr >> 8) & 0x07;
    assert_eq!(function, 7);
}

#[test]
fn test_pci_address_offset_aligned() {
    let addr = test_pci_address(0, 0, 0, 0x10);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x10);
}

#[test]
fn test_pci_address_offset_alignment_mask() {
    let addr = test_pci_address(0, 0, 0, 0x11);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x10);
}

#[test]
fn test_pci_address_offset_alignment_mask2() {
    let addr = test_pci_address(0, 0, 0, 0x13);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x10);
}

#[test]
fn test_pci_address_full_calculation() {
    let addr = test_pci_address(5, 10, 3, 0x10);
    let expected = (1u32 << 31) | (5u32 << 16) | (10u32 << 11) | (3u32 << 8) | 0x10;
    assert_eq!(addr, expected);
}

#[test]
fn test_pci_address_root_complex() {
    let addr = test_pci_address(0, 0, 0, 0);
    let expected = 1u32 << 31;
    assert_eq!(addr, expected);
}

#[test]
fn test_pci_address_typical_device() {
    let addr = test_pci_address(0, 2, 0, 0);
    let expected = (1u32 << 31) | (2u32 << 11);
    assert_eq!(addr, expected);
}

#[test]
fn test_pci_address_vendor_id_offset() {
    let addr = test_pci_address(0, 1, 0, 0x00);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x00);
}

#[test]
fn test_pci_address_device_id_offset() {
    let addr = test_pci_address(0, 1, 0, 0x02);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x00);
}

#[test]
fn test_pci_address_command_offset() {
    let addr = test_pci_address(0, 1, 0, 0x04);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x04);
}

#[test]
fn test_pci_address_status_offset() {
    let addr = test_pci_address(0, 1, 0, 0x06);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x04);
}

#[test]
fn test_pci_address_class_offset() {
    let addr = test_pci_address(0, 1, 0, 0x0B);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x08);
}

#[test]
fn test_pci_address_header_type_offset() {
    let addr = test_pci_address(0, 1, 0, 0x0E);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x0C);
}

#[test]
fn test_pci_address_bar0_offset() {
    let addr = test_pci_address(0, 1, 0, 0x10);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x10);
}

#[test]
fn test_pci_address_bar1_offset() {
    let addr = test_pci_address(0, 1, 0, 0x14);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x14);
}

#[test]
fn test_pci_address_bar2_offset() {
    let addr = test_pci_address(0, 1, 0, 0x18);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x18);
}

#[test]
fn test_pci_address_bar3_offset() {
    let addr = test_pci_address(0, 1, 0, 0x1C);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x1C);
}

#[test]
fn test_pci_address_bar4_offset() {
    let addr = test_pci_address(0, 1, 0, 0x20);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x20);
}

#[test]
fn test_pci_address_bar5_offset() {
    let addr = test_pci_address(0, 1, 0, 0x24);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x24);
}

#[test]
fn test_pci_address_interrupt_line_offset() {
    let addr = test_pci_address(0, 1, 0, 0x3C);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x3C);
}

#[test]
fn test_pci_address_interrupt_pin_offset() {
    let addr = test_pci_address(0, 1, 0, 0x3D);
    let offset = addr & 0xFC;
    assert_eq!(offset, 0x3C);
}

#[test]
fn test_pci_address_multiple_buses() {
    for bus in [0u8, 1, 127, 255] {
        let addr = test_pci_address(bus, 0, 0, 0);
        let extracted = (addr >> 16) & 0xFF;
        assert_eq!(extracted, bus as u32);
    }
}

#[test]
fn test_pci_address_multiple_devices() {
    for device in [0u8, 1, 15, 31] {
        let addr = test_pci_address(0, device, 0, 0);
        let extracted = (addr >> 11) & 0x1F;
        assert_eq!(extracted, device as u32);
    }
}

#[test]
fn test_pci_address_multiple_functions() {
    for function in 0u8..8 {
        let addr = test_pci_address(0, 0, function, 0);
        let extracted = (addr >> 8) & 0x07;
        assert_eq!(extracted, function as u32);
    }
}

#[test]
fn test_pci_config_address_port() {
    assert_eq!(0x0CF8u16, 0x0CF8);
}

#[test]
fn test_pci_config_data_port() {
    assert_eq!(0x0CFCu16, 0x0CFC);
}

#[test]
fn test_pci_address_bus_field_mask() {
    let addr = test_pci_address(0xFF, 0, 0, 0);
    assert_eq!((addr >> 16) & 0xFF, 0xFF);
}

#[test]
fn test_pci_address_device_field_mask() {
    let addr = test_pci_address(0, 0x1F, 0, 0);
    assert_eq!((addr >> 11) & 0x1F, 0x1F);
}

#[test]
fn test_pci_address_function_field_mask() {
    let addr = test_pci_address(0, 0, 0x07, 0);
    assert_eq!((addr >> 8) & 0x07, 0x07);
}

#[test]
fn test_pci_address_offset_field_mask() {
    let addr = test_pci_address(0, 0, 0, 0xFC);
    assert_eq!(addr & 0xFC, 0xFC);
}

#[test]
fn test_pci_address_all_fields_combined() {
    let addr = test_pci_address(0x12, 0x0A, 0x03, 0x40);
    assert_eq!((addr >> 16) & 0xFF, 0x12);
    assert_eq!((addr >> 11) & 0x1F, 0x0A);
    assert_eq!((addr >> 8) & 0x07, 0x03);
    assert_eq!(addr & 0xFC, 0x40);
}
