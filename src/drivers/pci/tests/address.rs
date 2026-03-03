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

use crate::drivers::pci::*;

#[test]
fn test_pci_address_creation() {
    let addr = types::PciAddress::new(0, 1, 2);
    assert_eq!(addr.bus, 0);
    assert_eq!(addr.device, 1);
    assert_eq!(addr.function, 2);
}

#[test]
fn test_pci_address_bdf_conversion() {
    let addr = types::PciAddress::new(5, 10, 3);
    let bdf = addr.to_bdf();
    let restored = types::PciAddress::from_bdf(bdf);

    assert_eq!(restored.bus, addr.bus);
    assert_eq!(restored.device, addr.device);
    assert_eq!(restored.function, addr.function);
}

#[test]
fn test_pci_address_display() {
    let addr = types::PciAddress::new(0x12, 0x0A, 0x03);
    let display = alloc::format!("{}", addr);
    assert_eq!(display, "12:0a.3");
}

#[test]
fn test_config_address_calculation() {
    let addr = constants::pci_config_address(0, 0, 0, 0);
    assert_eq!(addr & (1 << 31), 1 << 31);

    let addr = constants::pci_config_address(5, 10, 3, 0x10);
    let expected = (1u32 << 31) | (5u32 << 16) | (10u32 << 11) | (3u32 << 8) | 0x10;
    assert_eq!(addr, expected);
}
