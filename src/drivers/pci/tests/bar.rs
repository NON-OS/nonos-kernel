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
fn test_bar_offset_calculation() {
    assert_eq!(constants::bar_offset(0), constants::CFG_BAR0);
    assert_eq!(constants::bar_offset(1), constants::CFG_BAR1);
    assert_eq!(constants::bar_offset(5), constants::CFG_BAR5);
}

#[test]
fn test_pci_bar_properties() {
    let mem32 = types::PciBar::Memory32 {
        address: x86_64::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: true,
    };

    assert!(mem32.is_memory());
    assert!(!mem32.is_io());
    assert!(!mem32.is_64bit());
    assert!(mem32.is_prefetchable());
    assert!(mem32.is_present());
    assert_eq!(mem32.size(), 0x1000);
    assert_eq!(mem32.address(), Some(x86_64::PhysAddr::new(0xF000_0000)));

    let mem64 = types::PciBar::Memory64 {
        address: x86_64::PhysAddr::new(0x1_0000_0000),
        size: 0x100000,
        prefetchable: false,
    };

    assert!(mem64.is_64bit());
    assert!(!mem64.is_prefetchable());

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    assert!(io.is_io());
    assert!(!io.is_memory());
    assert_eq!(io.port(), Some(0x1000));

    let none = types::PciBar::NotPresent;
    assert!(!none.is_present());
}

#[test]
fn test_bar_alignment_calculation() {
    assert_eq!(bar::calculate_bar_alignment(0), 0);
    assert_eq!(bar::calculate_bar_alignment(1), 1);
    assert_eq!(bar::calculate_bar_alignment(100), 128);
    assert_eq!(bar::calculate_bar_alignment(256), 256);
    assert_eq!(bar::calculate_bar_alignment(1000), 1024);
}

#[test]
fn test_bar_type_identification() {
    let mem32 = types::PciBar::Memory32 {
        address: x86_64::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    assert_eq!(bar::bar_type(&mem32), error::BarType::Memory32);

    let mem64 = types::PciBar::Memory64 {
        address: x86_64::PhysAddr::new(0x1_0000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    assert_eq!(bar::bar_type(&mem64), error::BarType::Memory64);

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    assert_eq!(bar::bar_type(&io), error::BarType::Io);

    let none = types::PciBar::NotPresent;
    assert_eq!(bar::bar_type(&none), error::BarType::NotPresent);
}
