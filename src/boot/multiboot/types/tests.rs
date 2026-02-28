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
use x86_64::PhysAddr;

use super::*;

#[test]
fn test_memory_entry_helpers() {
    let entry = MemoryMapEntry {
        base_addr: 0x10_0000,
        length: 0x100_0000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };

    assert!(entry.is_available());
    assert_eq!(entry.start_addr().as_u64(), 0x10_0000);
    assert_eq!(entry.end_addr().as_u64(), 0x110_0000);
    assert_eq!(entry.size(), 0x100_0000);
    assert_eq!(entry.page_count(), 4096);
}

#[test]
fn test_memory_entry_reserved() {
    let entry = MemoryMapEntry {
        base_addr: 0,
        length: 0x10_0000,
        entry_type: memory_type::RESERVED,
        reserved: 0,
    };

    assert!(!entry.is_available());
}

#[test]
fn test_multiboot_info_helpers() {
    let info = MultibootInfo {
        memory_map: vec![
            MemoryMapEntry {
                base_addr: 0,
                length: 0x10_0000,
                entry_type: memory_type::RESERVED,
                reserved: 0,
            },
            MemoryMapEntry {
                base_addr: 0x10_0000,
                length: 0x100_0000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
        ],
        framebuffer_info: None,
        module_info: None,
    };

    assert_eq!(info.total_available_memory(), 0x100_0000);
    assert_eq!(info.usable_regions().count(), 1);
    assert!(!info.has_framebuffer());
    assert!(!info.has_module());
}

#[test]
fn test_framebuffer_helpers() {
    let fb = FramebufferInfo {
        addr: PhysAddr::new(0xFD00_0000),
        width: 800,
        height: 600,
        pitch: 3200,
        bpp: 32,
        framebuffer_type: 1,
    };

    assert_eq!(fb.size(), 3200 * 600);
    assert!(fb.is_rgb());
    assert!(!fb.is_text_mode());
}

#[test]
fn test_module_size() {
    let module = ModuleInfo {
        start: PhysAddr::new(0x20_0000),
        end: PhysAddr::new(0x30_0000),
        cmdline: Some("init=/bin/init"),
    };

    assert_eq!(module.size(), 0x10_0000);
}

#[test]
fn test_error_display() {
    let e = MultibootError::InvalidSize;
    assert_eq!(e.as_str(), "Invalid multiboot info size");

    let e = MultibootError::InvalidTag { tag_type: 99 };
    let s = alloc::format!("{}", e);
    assert!(s.contains("99"));
}
