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

extern crate alloc;

use alloc::vec;

use super::super::types::{MemoryMapEntry, MultibootInfo, memory_type};
use super::types::{Platform, ConsoleType};
use super::memory::get_safe_memory_regions;

#[test]
fn test_platform_display() {
    assert_eq!(Platform::Qemu.as_str(), "QEMU");
    assert_eq!(Platform::VirtualMachine.as_str(), "Virtual Machine");
    assert_eq!(Platform::BareMetal.as_str(), "Bare Metal");
}

#[test]
fn test_platform_is_virtual() {
    assert!(Platform::Qemu.is_virtual());
    assert!(Platform::VirtualMachine.is_virtual());
    assert!(!Platform::BareMetal.is_virtual());
}

#[test]
fn test_platform_virtio_support() {
    assert!(Platform::Qemu.supports_virtio());
    assert!(Platform::VirtualMachine.supports_virtio());
    assert!(!Platform::BareMetal.supports_virtio());
}

#[test]
fn test_console_type_display() {
    assert_eq!(ConsoleType::Serial.as_str(), "Serial");
    assert_eq!(ConsoleType::Vga.as_str(), "VGA");
    assert_eq!(ConsoleType::Framebuffer.as_str(), "Framebuffer");
}

#[test]
fn test_get_safe_memory_fallback() {
    let empty_info = MultibootInfo {
        memory_map: vec![],
        framebuffer_info: None,
        module_info: None,
    };

    let regions = get_safe_memory_regions(Platform::Qemu, &empty_info);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].start, 0x10_0000);
    assert_eq!(regions[0].end, 0x800_0000);
}
