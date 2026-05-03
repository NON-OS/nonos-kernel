// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::boot::multiboot::parser::tags::{
    tag_type, FramebufferTag, MemoryMapTag, ModuleTag, TagHeader,
};
use crate::test::framework::TestResult;

pub(crate) fn test_tag_type_constants() -> TestResult {
    if tag_type::END != 0 {
        return TestResult::Fail;
    }
    if tag_type::MODULE != 3 {
        return TestResult::Fail;
    }
    if tag_type::MMAP != 6 {
        return TestResult::Fail;
    }
    if tag_type::FRAMEBUFFER != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tag_header_size() -> TestResult {
    if core::mem::size_of::<TagHeader>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_tag_size() -> TestResult {
    if core::mem::size_of::<MemoryMapTag>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_tag_size() -> TestResult {
    if core::mem::size_of::<FramebufferTag>() < 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_tag_size() -> TestResult {
    if core::mem::size_of::<ModuleTag>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tag_header_layout() -> TestResult {
    let header = TagHeader { tag_type: tag_type::MMAP, size: 64 };
    if header.tag_type != 6 {
        return TestResult::Fail;
    }
    if header.size != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_map_tag_layout() -> TestResult {
    let tag = MemoryMapTag { tag_type: tag_type::MMAP, size: 64, entry_size: 24, entry_version: 0 };
    if tag.tag_type != tag_type::MMAP {
        return TestResult::Fail;
    }
    if tag.size != 64 {
        return TestResult::Fail;
    }
    if tag.entry_size != 24 {
        return TestResult::Fail;
    }
    if tag.entry_version != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_tag_layout() -> TestResult {
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
    if tag.tag_type != tag_type::FRAMEBUFFER {
        return TestResult::Fail;
    }
    if tag.framebuffer_addr != 0xFD000000 {
        return TestResult::Fail;
    }
    if tag.framebuffer_width != 800 {
        return TestResult::Fail;
    }
    if tag.framebuffer_height != 600 {
        return TestResult::Fail;
    }
    if tag.framebuffer_bpp != 32 {
        return TestResult::Fail;
    }
    if tag.framebuffer_type != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_tag_layout() -> TestResult {
    let tag =
        ModuleTag { tag_type: tag_type::MODULE, size: 24, mod_start: 0x200000, mod_end: 0x300000 };
    if tag.tag_type != tag_type::MODULE {
        return TestResult::Fail;
    }
    if tag.mod_start != 0x200000 {
        return TestResult::Fail;
    }
    if tag.mod_end != 0x300000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
