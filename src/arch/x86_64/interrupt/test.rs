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

use super::*;

#[test]
fn test_apic_feature_detection() {
    let _ = apic::has_xapic();
    let _ = apic::has_x2apic();
    let _ = apic::has_tsc_deadline();
}

#[test]
fn test_apic_divider_codes() {
    assert_eq!(apic::divider_to_code(1), 0b1011);
    assert_eq!(apic::divider_to_code(16), 0b0011);
    assert_eq!(apic::divider_to_code(128), 0b1010);
    assert_eq!(apic::divider_to_code(99), 0b0011);
}

#[test]
fn test_apic_calibration() {
    let ticks = apic::calibrate_timer(1000);
    assert!(ticks >= 50000);
}

#[test]
fn test_apic_error_messages() {
    assert_eq!(ApicError::NotSupported.as_str(), "APIC not supported");
    assert_eq!(ApicError::IcrBusy.as_str(), "ICR busy timeout");
}

#[test]
fn test_ioapic_rte_pack_unpack() {
    let orig = ioapic::Rte::fixed(42, 2);
    let (low, high) = orig.to_u32s();
    let unpacked = ioapic::Rte::from_u32s(low, high);
    assert_eq!(orig, unpacked);
}

#[test]
fn test_ioapic_rte_level_trigger() {
    let mut rte = ioapic::Rte::fixed(0x33, 0);
    rte.level_trigger = true;
    rte.active_low = true;
    let (low, _) = rte.to_u32s();
    assert!(low & (1 << 15) != 0);
    assert!(low & (1 << 13) != 0);
}

#[test]
fn test_ioapic_error_messages() {
    assert_eq!(IoApicError::GsiNotFound.as_str(), "GSI not found");
    assert_eq!(IoApicError::VectorExhausted.as_str(), "No vectors available");
}

#[test]
fn test_pic_mask_unmask_bits() {
    let mut v: u8 = 0b0000_0000;
    v |= 1 << 3;
    assert_eq!(v, 0b0000_1000);
    v &= !(1 << 3);
    assert_eq!(v, 0b0000_0000);
}

#[test]
fn test_pic_irq_validation() {
    for irq in 0..=15 {
        assert!(irq <= pic::MAX_IRQ);
    }
    assert!(16 > pic::MAX_IRQ);
}

#[test]
fn test_pic_error_messages() {
    assert_eq!(PicError::NotInitialized.as_str(), "PIC not initialized");
    assert_eq!(PicError::InvalidIrq.as_str(), "Invalid IRQ number (must be 0-15)");
}
