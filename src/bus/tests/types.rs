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
fn test_pci_device_empty_creation() {
    let dev = PciDevice::empty();
    assert_eq!(dev.bus, 0);
    assert_eq!(dev.device, 0);
    assert_eq!(dev.function, 0);
    assert_eq!(dev.vendor_id, 0xFFFF);
    assert_eq!(dev.device_id, 0xFFFF);
}

#[test]
fn test_pci_device_empty_is_invalid() {
    let dev = PciDevice::empty();
    assert!(!dev.is_valid());
}

#[test]
fn test_pci_device_with_valid_vendor_is_valid() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x8086;
    dev.device_id = 0x1234;
    assert!(dev.is_valid());
}

#[test]
fn test_pci_device_all_bars_initially_zero() {
    let dev = PciDevice::empty();
    assert_eq!(dev.bar0, 0);
    assert_eq!(dev.bar1, 0);
    assert_eq!(dev.bar2, 0);
    assert_eq!(dev.bar3, 0);
    assert_eq!(dev.bar4, 0);
    assert_eq!(dev.bar5, 0);
}

#[test]
fn test_pci_device_irq_fields() {
    let dev = PciDevice::empty();
    assert_eq!(dev.irq_line, 0);
    assert_eq!(dev.irq_pin, 0);
}

#[test]
fn test_pci_device_class_fields() {
    let dev = PciDevice::empty();
    assert_eq!(dev.class, 0);
    assert_eq!(dev.subclass, 0);
    assert_eq!(dev.prog_if, 0);
}

#[test]
fn test_pci_device_header_type() {
    let dev = PciDevice::empty();
    assert_eq!(dev.header_type, 0);
}

#[test]
fn test_pci_device_vendor_id_ffff_invalid() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0xFFFF;
    dev.device_id = 0x0000;
    assert!(!dev.is_valid());
}

#[test]
fn test_pci_device_vendor_id_zero_is_valid() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x0000;
    dev.device_id = 0x1234;
    assert!(dev.is_valid());
}

#[test]
fn test_pci_device_copy_trait() {
    let dev1 = PciDevice::empty();
    let dev2 = dev1;
    assert_eq!(dev1.vendor_id, dev2.vendor_id);
    assert_eq!(dev1.device_id, dev2.device_id);
}

#[test]
fn test_pci_device_clone_trait() {
    let dev1 = PciDevice::empty();
    let dev2 = dev1.clone();
    assert_eq!(dev1.vendor_id, dev2.vendor_id);
    assert_eq!(dev1.device_id, dev2.device_id);
}

#[test]
fn test_pci_device_multifunction_header() {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x80;
    assert_eq!(dev.header_type & 0x80, 0x80);
}

#[test]
fn test_pci_device_standard_header() {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x00;
    assert_eq!(dev.header_type & 0x7F, 0x00);
}

#[test]
fn test_pci_device_bridge_header() {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x01;
    assert_eq!(dev.header_type & 0x7F, 0x01);
}

#[test]
fn test_pci_device_cardbus_header() {
    let mut dev = PciDevice::empty();
    dev.header_type = 0x02;
    assert_eq!(dev.header_type & 0x7F, 0x02);
}

#[test]
fn test_pci_device_class_storage() {
    let mut dev = PciDevice::empty();
    dev.class = 0x01;
    dev.subclass = 0x08;
    assert_eq!(dev.class, 0x01);
    assert_eq!(dev.subclass, 0x08);
}

#[test]
fn test_pci_device_class_network() {
    let mut dev = PciDevice::empty();
    dev.class = 0x02;
    dev.subclass = 0x00;
    assert_eq!(dev.class, 0x02);
    assert_eq!(dev.subclass, 0x00);
}

#[test]
fn test_pci_device_class_display() {
    let mut dev = PciDevice::empty();
    dev.class = 0x03;
    dev.subclass = 0x00;
    assert_eq!(dev.class, 0x03);
}

#[test]
fn test_pci_device_class_serial_bus() {
    let mut dev = PciDevice::empty();
    dev.class = 0x0C;
    dev.subclass = 0x03;
    dev.prog_if = 0x30;
    assert_eq!(dev.class, 0x0C);
    assert_eq!(dev.subclass, 0x03);
    assert_eq!(dev.prog_if, 0x30);
}

#[test]
fn test_pci_device_bus_range() {
    let mut dev = PciDevice::empty();
    dev.bus = 255;
    assert_eq!(dev.bus, 255);
}

#[test]
fn test_pci_device_device_range() {
    let mut dev = PciDevice::empty();
    dev.device = 31;
    assert_eq!(dev.device, 31);
}

#[test]
fn test_pci_device_function_range() {
    let mut dev = PciDevice::empty();
    dev.function = 7;
    assert_eq!(dev.function, 7);
}

#[test]
fn test_pci_device_intel_vendor() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x8086;
    assert_eq!(dev.vendor_id, 0x8086);
    assert!(dev.is_valid());
}

#[test]
fn test_pci_device_amd_vendor() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x1022;
    assert_eq!(dev.vendor_id, 0x1022);
    assert!(dev.is_valid());
}

#[test]
fn test_pci_device_virtio_vendor() {
    let mut dev = PciDevice::empty();
    dev.vendor_id = 0x1AF4;
    assert_eq!(dev.vendor_id, 0x1AF4);
    assert!(dev.is_valid());
}
