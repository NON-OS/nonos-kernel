use crate::boot::multiboot::parser::tags::{tag_type, TagHeader, MemoryMapTag, FramebufferTag, ModuleTag};

#[test]
fn tag_type_constants() {
    assert_eq!(tag_type::END, 0);
    assert_eq!(tag_type::MODULE, 3);
    assert_eq!(tag_type::MMAP, 6);
    assert_eq!(tag_type::FRAMEBUFFER, 8);
}

#[test]
fn tag_header_size() {
    assert_eq!(core::mem::size_of::<TagHeader>(), 8);
}

#[test]
fn memory_map_tag_size() {
    assert_eq!(core::mem::size_of::<MemoryMapTag>(), 16);
}

#[test]
fn framebuffer_tag_size() {
    assert!(core::mem::size_of::<FramebufferTag>() >= 31);
}

#[test]
fn module_tag_size() {
    assert_eq!(core::mem::size_of::<ModuleTag>(), 16);
}

#[test]
fn tag_header_layout() {
    let header = TagHeader {
        tag_type: tag_type::MMAP,
        size: 64,
    };
    assert_eq!(header.tag_type, 6);
    assert_eq!(header.size, 64);
}

#[test]
fn memory_map_tag_layout() {
    let tag = MemoryMapTag {
        tag_type: tag_type::MMAP,
        size: 64,
        entry_size: 24,
        entry_version: 0,
    };
    assert_eq!(tag.tag_type, tag_type::MMAP);
    assert_eq!(tag.size, 64);
    assert_eq!(tag.entry_size, 24);
    assert_eq!(tag.entry_version, 0);
}

#[test]
fn framebuffer_tag_layout() {
    let tag = FramebufferTag {
        tag_type: tag_type::FRAMEBUFFER,
        size: 31,
        framebuffer_addr: 0xFD000000,
        framebuffer_pitch: 3200,
        framebuffer_width: 800,
        framebuffer_height: 600,
        framebuffer_bpp: 32,
        framebuffer_type: 1,
        reserved: 0,
    };
    assert_eq!(tag.tag_type, tag_type::FRAMEBUFFER);
    assert_eq!(tag.framebuffer_addr, 0xFD000000);
    assert_eq!(tag.framebuffer_width, 800);
    assert_eq!(tag.framebuffer_height, 600);
    assert_eq!(tag.framebuffer_bpp, 32);
    assert_eq!(tag.framebuffer_type, 1);
}

#[test]
fn module_tag_layout() {
    let tag = ModuleTag {
        tag_type: tag_type::MODULE,
        size: 24,
        mod_start: 0x200000,
        mod_end: 0x300000,
    };
    assert_eq!(tag.tag_type, tag_type::MODULE);
    assert_eq!(tag.mod_start, 0x200000);
    assert_eq!(tag.mod_end, 0x300000);
}
