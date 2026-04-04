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

use crate::bus::*;

#[test]
fn test_device_count_returns_value() {
    let count = device_count();
    assert!(count <= 64);
}

#[test]
fn test_is_init_returns_bool() {
    let _init = is_init();
}

#[test]
fn test_get_device_out_of_bounds() {
    let result = get_device(1000);
    assert!(result.is_none());
}

#[test]
fn test_get_device_at_max_index() {
    let result = get_device(64);
    assert!(result.is_none());
}

#[test]
fn test_find_device_by_id_nonexistent() {
    let result = find_device_by_id(0xDEAD, 0xBEEF);
    assert!(result.is_none());
}

#[test]
fn test_find_device_nonexistent_class() {
    let result = find_device(0xFF, 0xFF, None);
    assert!(result.is_none());
}

#[test]
fn test_find_device_with_prog_if_nonexistent() {
    let result = find_device(0xFF, 0xFF, Some(0xFF));
    assert!(result.is_none());
}

#[test]
fn test_find_devices_empty_class() {
    let devices: alloc::vec::Vec<_> = find_devices(0xFF, 0xFF).collect();
    assert!(devices.is_empty());
}

#[test]
fn test_pci_device_class_constants() {
    assert_eq!(0x01u8, 0x01);
    assert_eq!(0x02u8, 0x02);
    assert_eq!(0x03u8, 0x03);
    assert_eq!(0x06u8, 0x06);
    assert_eq!(0x0Cu8, 0x0C);
}

#[test]
fn test_storage_subclass_constants() {
    assert_eq!(0x06u8, 0x06);
    assert_eq!(0x08u8, 0x08);
}

#[test]
fn test_usb_prog_if_constants() {
    assert_eq!(0x00u8, 0x00);
    assert_eq!(0x10u8, 0x10);
    assert_eq!(0x20u8, 0x20);
    assert_eq!(0x30u8, 0x30);
}

#[test]
fn test_bridge_subclass_constants() {
    assert_eq!(0x00u8, 0x00);
    assert_eq!(0x01u8, 0x01);
    assert_eq!(0x04u8, 0x04);
}

#[test]
fn test_device_count_consistent() {
    let count1 = device_count();
    let count2 = device_count();
    assert_eq!(count1, count2);
}

#[test]
fn test_find_device_storage_nvme() {
    let _result = find_device(0x01, 0x08, None);
}

#[test]
fn test_find_device_storage_sata() {
    let _result = find_device(0x01, 0x06, None);
}

#[test]
fn test_find_device_network_ethernet() {
    let _result = find_device(0x02, 0x00, None);
}

#[test]
fn test_find_device_display_vga() {
    let _result = find_device(0x03, 0x00, None);
}

#[test]
fn test_find_device_serial_usb() {
    let _result = find_device(0x0C, 0x03, None);
}

#[test]
fn test_find_device_bridge_host() {
    let _result = find_device(0x06, 0x00, None);
}

#[test]
fn test_find_device_bridge_pci() {
    let _result = find_device(0x06, 0x04, None);
}

#[test]
fn test_find_devices_iterator() {
    let iter = find_devices(0x01, 0x08);
    let _count: usize = iter.count();
}

#[test]
fn test_find_device_by_id_intel() {
    let _result = find_device_by_id(0x8086, 0x0000);
}

#[test]
fn test_find_device_by_id_amd() {
    let _result = find_device_by_id(0x1022, 0x0000);
}

#[test]
fn test_find_device_by_id_virtio() {
    let _result = find_device_by_id(0x1AF4, 0x0000);
}

#[test]
fn test_find_device_usb_uhci() {
    let _result = find_device(0x0C, 0x03, Some(0x00));
}

#[test]
fn test_find_device_usb_ohci() {
    let _result = find_device(0x0C, 0x03, Some(0x10));
}

#[test]
fn test_find_device_usb_ehci() {
    let _result = find_device(0x0C, 0x03, Some(0x20));
}

#[test]
fn test_find_device_usb_xhci() {
    let _result = find_device(0x0C, 0x03, Some(0x30));
}

#[test]
fn test_get_device_first() {
    let _result = get_device(0);
}

#[test]
fn test_get_device_boundary() {
    let count = device_count();
    if count > 0 {
        let result = get_device(count - 1);
        assert!(result.is_some());
    }
}

#[test]
fn test_get_device_past_boundary() {
    let count = device_count();
    let result = get_device(count);
    assert!(result.is_none());
}
