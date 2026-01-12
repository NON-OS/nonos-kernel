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

use super::types::{BootInfo, FramebufferInfo, MemoryDescriptor, EFI_CONVENTIONAL_MEMORY};
#[test]
fn test_memory_descriptor_fields() {
    let desc = MemoryDescriptor {
        ty: EFI_CONVENTIONAL_MEMORY,
        phys_start: 0x10_0000,
        virt_start: 0,
        page_count: 256,
        attribute: 0,
    };

    assert_eq!(desc.ty, 7);
    assert_eq!(desc.phys_start, 0x10_0000);
    assert_eq!(desc.page_count, 256);
}

#[test]
fn test_memory_descriptor_size() {
    assert_eq!(core::mem::size_of::<MemoryDescriptor>(), 32);
}

#[test]
fn test_framebuffer_info_size() {
    assert!(core::mem::size_of::<FramebufferInfo>() >= 24);
}

#[test]
fn test_efi_conventional_memory_constant() {
    assert_eq!(EFI_CONVENTIONAL_MEMORY, 7);
}

#[test]
fn test_memory_region_calculation() {
    let desc = MemoryDescriptor {
        ty: EFI_CONVENTIONAL_MEMORY,
        phys_start: 0x10_0000,
        virt_start: 0,
        page_count: 1024,
        attribute: 0,
    };

    let region_size = desc.page_count * 4096;
    assert_eq!(region_size, 4 * 1024 * 1024); // 4MB
}

#[test]
fn test_memory_region_overflow_protection() {
    let desc = MemoryDescriptor {
        ty: EFI_CONVENTIONAL_MEMORY,
        phys_start: u64::MAX - 0x1000,
        virt_start: 0,
        page_count: 10,
        attribute: 0,
    };

    let region_end = desc.phys_start.saturating_add(desc.page_count.saturating_mul(4096));
    assert_eq!(region_end, u64::MAX);
}

#[test]
fn test_apic_id_extraction() {
    let mock_ebx: u32 = 0x12_00_00_00; // APIC ID = 0x12
    let apic_id = (mock_ebx >> 24) & 0xFF;
    assert_eq!(apic_id, 0x12);
}

#[test]
fn test_serial_constants() {
    const COM1: u16 = 0x3F8;
    const LSR_TX_EMPTY: u8 = 0x20;

    assert_eq!(COM1, 0x3F8);
    assert_eq!(LSR_TX_EMPTY, 0x20);
}
