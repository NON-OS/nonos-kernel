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

extern crate alloc;

use alloc::format;
use core::sync::atomic::Ordering;
use x86_64::PhysAddr;

use super::constants::{memory_type, tag, MULTIBOOT2_ARCHITECTURE_I386, MULTIBOOT2_HEADER_MAGIC};
use super::error::MultibootError;
use super::framebuffer::FramebufferType;
use super::header::Multiboot2Header;
use super::memory_map::MemoryMapEntry;
use super::modules::{AcpiRsdp, ModuleInfo};
use super::platform::{ConsoleType, Platform};
use super::stats::MultibootStats;

#[test]
fn test_multiboot_header_checksum() {
    let header = Multiboot2Header::new(16);
    assert!(header.verify_checksum());
    assert_eq!(header.magic, MULTIBOOT2_HEADER_MAGIC);
    assert_eq!(header.architecture, MULTIBOOT2_ARCHITECTURE_I386);
}

#[test]
fn test_memory_map_entry() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };

    assert!(entry.is_available());
    assert!(!entry.is_acpi_reclaimable());
    assert_eq!(entry.type_name(), "Available");
    assert_eq!(entry.start_addr().as_u64(), 0x100000);
    assert_eq!(entry.end_addr().as_u64(), 0x1100000);
}

#[test]
fn test_memory_type_names() {
    assert_eq!(memory_type::name(1), "Available");
    assert_eq!(memory_type::name(2), "Reserved");
    assert_eq!(memory_type::name(3), "ACPI Reclaimable");
    assert_eq!(memory_type::name(4), "ACPI NVS");
    assert_eq!(memory_type::name(5), "Bad Memory");
    assert_eq!(memory_type::name(99), "Unknown");
}

#[test]
fn test_tag_type_names() {
    assert_eq!(tag::name(0), "End");
    assert_eq!(tag::name(1), "Command Line");
    assert_eq!(tag::name(6), "Memory Map");
    assert_eq!(tag::name(8), "Framebuffer");
    assert_eq!(tag::name(14), "ACPI Old RSDP");
    assert_eq!(tag::name(15), "ACPI New RSDP");
    assert_eq!(tag::name(255), "Unknown");
}

#[test]
fn test_framebuffer_type() {
    assert_eq!(FramebufferType::from(0), FramebufferType::Indexed);
    assert_eq!(FramebufferType::from(1), FramebufferType::DirectRgb);
    assert_eq!(FramebufferType::from(2), FramebufferType::EgaText);
    assert_eq!(FramebufferType::from(99), FramebufferType::Unknown(99));
}

#[test]
fn test_platform_properties() {
    assert!(Platform::QemuTcg.is_virtual());
    assert!(Platform::QemuKvm.is_virtual());
    assert!(Platform::Vmware.is_virtual());
    assert!(!Platform::BareMetal.is_virtual());

    assert!(Platform::QemuTcg.is_qemu());
    assert!(Platform::QemuKvm.is_qemu());
    assert!(!Platform::Vmware.is_qemu());

    assert!(Platform::QemuKvm.has_hw_virtualization());
    assert!(Platform::Kvm.has_hw_virtualization());
    assert!(!Platform::QemuTcg.has_hw_virtualization());

    assert!(Platform::QemuTcg.supports_virtio());
    assert!(Platform::QemuKvm.supports_virtio());
    assert!(!Platform::Vmware.supports_virtio());
}

#[test]
fn test_platform_names() {
    assert_eq!(Platform::QemuTcg.name(), "QEMU (TCG)");
    assert_eq!(Platform::QemuKvm.name(), "QEMU (KVM)");
    assert_eq!(Platform::Vmware.name(), "VMware");
    assert_eq!(Platform::HyperV.name(), "Microsoft Hyper-V");
    assert_eq!(Platform::BareMetal.name(), "Bare Metal");
}

#[test]
fn test_console_types() {
    assert_eq!(Platform::QemuTcg.console_type(), ConsoleType::Serial);
    assert_eq!(Platform::Vmware.console_type(), ConsoleType::Vga);
    assert_eq!(Platform::HyperV.console_type(), ConsoleType::EfiConsole);
}

#[test]
fn test_timer_frequencies() {
    assert_eq!(Platform::QemuTcg.timer_frequency(), 100);
    assert_eq!(Platform::QemuKvm.timer_frequency(), 1000);
    assert_eq!(Platform::BareMetal.timer_frequency(), 1000);
}

#[test]
fn test_error_messages() {
    assert_eq!(
        MultibootError::InvalidMagic {
            expected: 0,
            found: 1
        }
        .as_str(),
        "Invalid multiboot magic number"
    );
    assert_eq!(
        MultibootError::NotInitialized.as_str(),
        "Multiboot subsystem not initialized"
    );
    assert_eq!(
        MultibootError::NoMemoryMap.as_str(),
        "No memory map available"
    );
}

#[test]
fn test_module_info_size() {
    let module = ModuleInfo {
        start: PhysAddr::new(0x100000),
        end: PhysAddr::new(0x200000),
        cmdline: Some("test module".into()),
    };
    assert_eq!(module.size(), 0x100000);
}

#[test]
fn test_acpi_rsdp_is_acpi2() {
    let rsdp_v1 = AcpiRsdp {
        signature: *b"RSD PTR ",
        checksum: 0,
        oem_id: [0; 6],
        revision: 0,
        rsdt_address: 0x12345678,
        length: None,
        xsdt_address: None,
        extended_checksum: None,
    };
    assert!(!rsdp_v1.is_acpi2());
    assert_eq!(rsdp_v1.table_address(), 0x12345678);

    let rsdp_v2 = AcpiRsdp {
        signature: *b"RSD PTR ",
        checksum: 0,
        oem_id: [0; 6],
        revision: 2,
        rsdt_address: 0x12345678,
        length: Some(36),
        xsdt_address: Some(0xDEADBEEF00000000),
        extended_checksum: Some(0),
    };
    assert!(rsdp_v2.is_acpi2());
    assert_eq!(rsdp_v2.table_address(), 0xDEADBEEF00000000);
}

#[test]
fn test_acpi_rsdp_checksum() {
    let rsdp = AcpiRsdp {
        signature: *b"RSD PTR ",
        checksum: 0x41,
        oem_id: [0; 6],
        revision: 0,
        rsdt_address: 0,
        length: None,
        xsdt_address: None,
        extended_checksum: None,
    };
    assert!(rsdp.verify_checksum());

    let bad_rsdp = AcpiRsdp {
        signature: *b"RSD PTR ",
        checksum: 0x00,
        oem_id: [0; 6],
        revision: 0,
        rsdt_address: 0,
        length: None,
        xsdt_address: None,
        extended_checksum: None,
    };
    assert!(!bad_rsdp.verify_checksum());
}

#[test]
fn test_error_display() {
    let err = MultibootError::InvalidMagic {
        expected: 0x36D76289,
        found: 0xDEADBEEF,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("0x36D76289"));
    assert!(msg.contains("0xDEADBEEF"));

    let err = MultibootError::AlignmentError {
        expected: 8,
        found: 3,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("8-byte"));
    assert!(msg.contains("3"));

    let err = MultibootError::MalformedTag {
        tag_type: tag::MEMORY_MAP,
        reason: "test reason",
    };
    let msg = format!("{}", err);
    assert!(msg.contains("Memory Map"));
    assert!(msg.contains("test reason"));
}

#[test]
fn test_multiboot_stats() {
    let stats = MultibootStats::new();
    assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 0);

    stats.memory_entries_parsed.fetch_add(5, Ordering::SeqCst);
    assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 5);

    stats.reset();
    assert_eq!(stats.memory_entries_parsed.load(Ordering::SeqCst), 0);
}
