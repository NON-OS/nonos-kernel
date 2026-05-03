// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::boot::multiboot::types::*;
use crate::memory::addr::PhysAddr;
use crate::test::framework::TestResult;
use alloc::vec;

pub(crate) fn test_memory_type_constants() -> TestResult {
    if memory_type::AVAILABLE != 1 {
        return TestResult::Fail;
    }
    if memory_type::RESERVED != 2 {
        return TestResult::Fail;
    }
    if memory_type::ACPI_RECLAIMABLE != 3 {
        return TestResult::Fail;
    }
    if memory_type::ACPI_NVS != 4 {
        return TestResult::Fail;
    }
    if memory_type::BAD_MEMORY != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_is_available() -> TestResult {
    let available = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if !available.is_available() {
        return TestResult::Fail;
    }
    let reserved = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::RESERVED,
        reserved: 0,
    };
    if reserved.is_available() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_start_addr() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.start_addr() != PhysAddr::new(0x100000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_end_addr() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.end_addr() != PhysAddr::new(0x101000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_size() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x2000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.size() != 0x2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_page_count() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x8000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.page_count() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_page_count_partial() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1500,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.page_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_end_addr_saturating() -> TestResult {
    let entry = MemoryMapEntry {
        base_addr: u64::MAX - 0x100,
        length: 0x200,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    if entry.end_addr() != PhysAddr::new(u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_invalid_size_str() -> TestResult {
    let err = MultibootError::InvalidSize;
    if err.as_str() != "Invalid multiboot info size" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_invalid_tag_str() -> TestResult {
    let err = MultibootError::InvalidTag { tag_type: 42 };
    if err.as_str() != "Invalid multiboot tag" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_memory_map_str() -> TestResult {
    let err = MultibootError::MemoryMapError;
    if err.as_str() != "Memory map parsing failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_framebuffer_str() -> TestResult {
    let err = MultibootError::FramebufferError;
    if err.as_str() != "Framebuffer info parsing failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_module_str() -> TestResult {
    let err = MultibootError::ModuleError;
    if err.as_str() != "Module info parsing failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_invalid_cmdline_str() -> TestResult {
    let err = MultibootError::InvalidCmdline;
    if err.as_str() != "Invalid UTF-8 in command line" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_error_equality() -> TestResult {
    if MultibootError::InvalidSize != MultibootError::InvalidSize {
        return TestResult::Fail;
    }
    let e1 = MultibootError::InvalidTag { tag_type: 1 };
    let e2 = MultibootError::InvalidTag { tag_type: 1 };
    let e3 = MultibootError::InvalidTag { tag_type: 2 };
    if e1 != e2 {
        return TestResult::Fail;
    }
    if e1 == e3 {
        return TestResult::Fail;
    }
    if MultibootError::InvalidSize == MultibootError::MemoryMapError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot2_header_repr() -> TestResult {
    if core::mem::size_of::<Multiboot2Header>() != 16 {
        return TestResult::Fail;
    }
    if core::mem::align_of::<Multiboot2Header>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot2_info_repr() -> TestResult {
    if core::mem::size_of::<Multiboot2Info>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_entry_repr() -> TestResult {
    if core::mem::size_of::<MemoryMapEntry>() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_total_available_memory_empty() -> TestResult {
    let info = MultibootInfo { memory_map: vec![], framebuffer_info: None, module_info: None };
    if info.total_available_memory() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_total_available_memory_single() -> TestResult {
    let info = MultibootInfo {
        memory_map: vec![MemoryMapEntry {
            base_addr: 0x100000,
            length: 0x10000,
            entry_type: memory_type::AVAILABLE,
            reserved: 0,
        }],
        framebuffer_info: None,
        module_info: None,
    };
    if info.total_available_memory() != 0x10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_total_available_memory_mixed() -> TestResult {
    let info = MultibootInfo {
        memory_map: vec![
            MemoryMapEntry {
                base_addr: 0x100000,
                length: 0x10000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
            MemoryMapEntry {
                base_addr: 0x200000,
                length: 0x5000,
                entry_type: memory_type::RESERVED,
                reserved: 0,
            },
            MemoryMapEntry {
                base_addr: 0x300000,
                length: 0x8000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
        ],
        framebuffer_info: None,
        module_info: None,
    };
    if info.total_available_memory() != 0x18000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_has_framebuffer_none() -> TestResult {
    let info = MultibootInfo { memory_map: vec![], framebuffer_info: None, module_info: None };
    if info.has_framebuffer() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_has_framebuffer_some() -> TestResult {
    let info = MultibootInfo {
        memory_map: vec![],
        framebuffer_info: Some(FramebufferInfo {
            addr: PhysAddr::new(0xB8000),
            width: 80,
            height: 25,
            pitch: 160,
            bpp: 16,
            framebuffer_type: 2,
        }),
        module_info: None,
    };
    if !info.has_framebuffer() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_has_module_none() -> TestResult {
    let info = MultibootInfo { memory_map: vec![], framebuffer_info: None, module_info: None };
    if info.has_module() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiboot_info_has_module_some() -> TestResult {
    let info = MultibootInfo {
        memory_map: vec![],
        framebuffer_info: None,
        module_info: Some(ModuleInfo {
            start: PhysAddr::new(0x200000),
            end: PhysAddr::new(0x300000),
            cmdline: None,
        }),
    };
    if !info.has_module() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_size() -> TestResult {
    let fb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 1920,
        height: 1080,
        pitch: 7680,
        bpp: 32,
        framebuffer_type: 1,
    };
    if fb.size() != 7680 * 1080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_is_rgb() -> TestResult {
    let fb_rgb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 800,
        height: 600,
        pitch: 3200,
        bpp: 32,
        framebuffer_type: 1,
    };
    if !fb_rgb.is_rgb() {
        return TestResult::Fail;
    }
    let fb_text = FramebufferInfo {
        addr: PhysAddr::new(0xB8000),
        width: 80,
        height: 25,
        pitch: 160,
        bpp: 16,
        framebuffer_type: 2,
    };
    if fb_text.is_rgb() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_is_text_mode() -> TestResult {
    let fb_text = FramebufferInfo {
        addr: PhysAddr::new(0xB8000),
        width: 80,
        height: 25,
        pitch: 160,
        bpp: 16,
        framebuffer_type: 2,
    };
    if !fb_text.is_text_mode() {
        return TestResult::Fail;
    }
    let fb_rgb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 800,
        height: 600,
        pitch: 3200,
        bpp: 32,
        framebuffer_type: 1,
    };
    if fb_rgb.is_text_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_info_size() -> TestResult {
    let module =
        ModuleInfo { start: PhysAddr::new(0x200000), end: PhysAddr::new(0x300000), cmdline: None };
    if module.size() != 0x100000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_info_size_saturating() -> TestResult {
    let module =
        ModuleInfo { start: PhysAddr::new(0x300000), end: PhysAddr::new(0x200000), cmdline: None };
    if module.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_info_with_cmdline() -> TestResult {
    let module = ModuleInfo {
        start: PhysAddr::new(0x200000),
        end: PhysAddr::new(0x300000),
        cmdline: Some("init=/bin/sh"),
    };
    if module.cmdline != Some("init=/bin/sh") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
