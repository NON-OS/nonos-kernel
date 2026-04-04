use crate::boot::multiboot::types::*;
use x86_64::PhysAddr;

#[test]
fn memory_type_constants() {
    assert_eq!(memory_type::AVAILABLE, 1);
    assert_eq!(memory_type::RESERVED, 2);
    assert_eq!(memory_type::ACPI_RECLAIMABLE, 3);
    assert_eq!(memory_type::ACPI_NVS, 4);
    assert_eq!(memory_type::BAD_MEMORY, 5);
}

#[test]
fn memory_map_entry_is_available() {
    let available = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert!(available.is_available());

    let reserved = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::RESERVED,
        reserved: 0,
    };
    assert!(!reserved.is_available());
}

#[test]
fn memory_map_entry_start_addr() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.start_addr(), PhysAddr::new(0x100000));
}

#[test]
fn memory_map_entry_end_addr() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.end_addr(), PhysAddr::new(0x101000));
}

#[test]
fn memory_map_entry_size() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x2000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.size(), 0x2000);
}

#[test]
fn memory_map_entry_page_count() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x8000,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.page_count(), 8);
}

#[test]
fn memory_map_entry_page_count_partial() {
    let entry = MemoryMapEntry {
        base_addr: 0x100000,
        length: 0x1500,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.page_count(), 1);
}

#[test]
fn memory_map_entry_end_addr_saturating() {
    let entry = MemoryMapEntry {
        base_addr: u64::MAX - 0x100,
        length: 0x200,
        entry_type: memory_type::AVAILABLE,
        reserved: 0,
    };
    assert_eq!(entry.end_addr(), PhysAddr::new(u64::MAX));
}

#[test]
fn multiboot_error_invalid_size_str() {
    let err = MultibootError::InvalidSize;
    assert_eq!(err.as_str(), "Invalid multiboot info size");
}

#[test]
fn multiboot_error_invalid_tag_str() {
    let err = MultibootError::InvalidTag { tag_type: 42 };
    assert_eq!(err.as_str(), "Invalid multiboot tag");
}

#[test]
fn multiboot_error_memory_map_str() {
    let err = MultibootError::MemoryMapError;
    assert_eq!(err.as_str(), "Memory map parsing failed");
}

#[test]
fn multiboot_error_framebuffer_str() {
    let err = MultibootError::FramebufferError;
    assert_eq!(err.as_str(), "Framebuffer info parsing failed");
}

#[test]
fn multiboot_error_module_str() {
    let err = MultibootError::ModuleError;
    assert_eq!(err.as_str(), "Module info parsing failed");
}

#[test]
fn multiboot_error_invalid_cmdline_str() {
    let err = MultibootError::InvalidCmdline;
    assert_eq!(err.as_str(), "Invalid UTF-8 in command line");
}

#[test]
fn multiboot_error_display_invalid_tag() {
    use alloc::string::ToString;
    let err = MultibootError::InvalidTag { tag_type: 99 };
    assert_eq!(err.to_string(), "Invalid multiboot tag type: 99");
}

#[test]
fn multiboot_error_display_other() {
    use alloc::string::ToString;
    let err = MultibootError::InvalidSize;
    assert_eq!(err.to_string(), "Invalid multiboot info size");
}

#[test]
fn multiboot_error_equality() {
    assert_eq!(MultibootError::InvalidSize, MultibootError::InvalidSize);
    assert_eq!(
        MultibootError::InvalidTag { tag_type: 1 },
        MultibootError::InvalidTag { tag_type: 1 }
    );
    assert_ne!(
        MultibootError::InvalidTag { tag_type: 1 },
        MultibootError::InvalidTag { tag_type: 2 }
    );
    assert_ne!(MultibootError::InvalidSize, MultibootError::MemoryMapError);
}

#[test]
fn multiboot2_header_repr() {
    assert_eq!(core::mem::size_of::<Multiboot2Header>(), 16);
    assert_eq!(core::mem::align_of::<Multiboot2Header>(), 8);
}

#[test]
fn multiboot2_info_repr() {
    assert_eq!(core::mem::size_of::<Multiboot2Info>(), 8);
}

#[test]
fn memory_map_entry_repr() {
    assert_eq!(core::mem::size_of::<MemoryMapEntry>(), 24);
}

#[test]
fn multiboot_info_total_available_memory_empty() {
    let info = MultibootInfo {
        memory_map: alloc::vec![],
        framebuffer_info: None,
        module_info: None,
    };
    assert_eq!(info.total_available_memory(), 0);
}

#[test]
fn multiboot_info_total_available_memory_single() {
    let info = MultibootInfo {
        memory_map: alloc::vec![MemoryMapEntry {
            base_addr: 0x100000,
            length: 0x10000,
            entry_type: memory_type::AVAILABLE,
            reserved: 0,
        }],
        framebuffer_info: None,
        module_info: None,
    };
    assert_eq!(info.total_available_memory(), 0x10000);
}

#[test]
fn multiboot_info_total_available_memory_mixed() {
    let info = MultibootInfo {
        memory_map: alloc::vec![
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
    assert_eq!(info.total_available_memory(), 0x18000);
}

#[test]
fn multiboot_info_usable_regions_filters_low_memory() {
    let info = MultibootInfo {
        memory_map: alloc::vec![
            MemoryMapEntry {
                base_addr: 0x0,
                length: 0x80000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
            MemoryMapEntry {
                base_addr: 0x100000,
                length: 0x10000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
        ],
        framebuffer_info: None,
        module_info: None,
    };
    let regions: alloc::vec::Vec<_> = info.usable_regions().collect();
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].base_addr, 0x100000);
}

#[test]
fn multiboot_info_usable_regions_filters_reserved() {
    let info = MultibootInfo {
        memory_map: alloc::vec![
            MemoryMapEntry {
                base_addr: 0x100000,
                length: 0x10000,
                entry_type: memory_type::AVAILABLE,
                reserved: 0,
            },
            MemoryMapEntry {
                base_addr: 0x200000,
                length: 0x10000,
                entry_type: memory_type::RESERVED,
                reserved: 0,
            },
        ],
        framebuffer_info: None,
        module_info: None,
    };
    let regions: alloc::vec::Vec<_> = info.usable_regions().collect();
    assert_eq!(regions.len(), 1);
}

#[test]
fn multiboot_info_has_framebuffer_none() {
    let info = MultibootInfo {
        memory_map: alloc::vec![],
        framebuffer_info: None,
        module_info: None,
    };
    assert!(!info.has_framebuffer());
}

#[test]
fn multiboot_info_has_framebuffer_some() {
    let info = MultibootInfo {
        memory_map: alloc::vec![],
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
    assert!(info.has_framebuffer());
}

#[test]
fn multiboot_info_has_module_none() {
    let info = MultibootInfo {
        memory_map: alloc::vec![],
        framebuffer_info: None,
        module_info: None,
    };
    assert!(!info.has_module());
}

#[test]
fn multiboot_info_has_module_some() {
    let info = MultibootInfo {
        memory_map: alloc::vec![],
        framebuffer_info: None,
        module_info: Some(ModuleInfo {
            start: PhysAddr::new(0x200000),
            end: PhysAddr::new(0x300000),
            cmdline: None,
        }),
    };
    assert!(info.has_module());
}

#[test]
fn framebuffer_info_size() {
    let fb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 1920,
        height: 1080,
        pitch: 7680,
        bpp: 32,
        framebuffer_type: 1,
    };
    assert_eq!(fb.size(), 7680 * 1080);
}

#[test]
fn framebuffer_info_is_rgb() {
    let fb_rgb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 800,
        height: 600,
        pitch: 3200,
        bpp: 32,
        framebuffer_type: 1,
    };
    assert!(fb_rgb.is_rgb());

    let fb_text = FramebufferInfo {
        addr: PhysAddr::new(0xB8000),
        width: 80,
        height: 25,
        pitch: 160,
        bpp: 16,
        framebuffer_type: 2,
    };
    assert!(!fb_text.is_rgb());
}

#[test]
fn framebuffer_info_is_text_mode() {
    let fb_text = FramebufferInfo {
        addr: PhysAddr::new(0xB8000),
        width: 80,
        height: 25,
        pitch: 160,
        bpp: 16,
        framebuffer_type: 2,
    };
    assert!(fb_text.is_text_mode());

    let fb_rgb = FramebufferInfo {
        addr: PhysAddr::new(0xFD000000),
        width: 800,
        height: 600,
        pitch: 3200,
        bpp: 32,
        framebuffer_type: 1,
    };
    assert!(!fb_rgb.is_text_mode());
}

#[test]
fn module_info_size() {
    let module = ModuleInfo {
        start: PhysAddr::new(0x200000),
        end: PhysAddr::new(0x300000),
        cmdline: None,
    };
    assert_eq!(module.size(), 0x100000);
}

#[test]
fn module_info_size_saturating() {
    let module = ModuleInfo {
        start: PhysAddr::new(0x300000),
        end: PhysAddr::new(0x200000),
        cmdline: None,
    };
    assert_eq!(module.size(), 0);
}

#[test]
fn module_info_with_cmdline() {
    let module = ModuleInfo {
        start: PhysAddr::new(0x200000),
        end: PhysAddr::new(0x300000),
        cmdline: Some("init=/bin/sh"),
    };
    assert_eq!(module.cmdline, Some("init=/bin/sh"));
}
