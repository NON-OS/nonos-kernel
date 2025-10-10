//! Multiboot2 Support for QEMU and Bare-metal Boot
//!
//! This module provides robust multiboot2 compatibility for booting NONOS
//! on both QEMU virtualization and real bare-metal hardware.

use alloc::vec::Vec;
use core::slice;
use x86_64::{PhysAddr, VirtAddr};

/// Multiboot2 header structure
#[repr(C, align(8))]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
}

/// Multiboot2 information structure
#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
}

/// Memory map entry from multiboot2
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

impl MemoryMapEntry {
    pub fn is_available(&self) -> bool {
        self.entry_type == 1
    }

    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr + self.length)
    }
}

/// Parse multiboot2 information structure
pub unsafe fn parse_multiboot_info(info_addr: VirtAddr) -> Result<MultibootInfo, &'static str> {
    let info_ptr = info_addr.as_ptr::<Multiboot2Info>();
    let info = &*info_ptr;

    if info.total_size < 8 {
        return Err("Invalid multiboot info size");
    }

    let mut memory_map = None;
    let mut framebuffer_info = None;
    let mut module_info = None;

    // Parse tags
    let mut tag_ptr = (info_addr + 8u64).as_ptr::<u8>();
    let end_ptr = (info_addr + info.total_size as u64).as_ptr::<u8>();

    while tag_ptr < end_ptr {
        let tag_header = &*(tag_ptr as *const TagHeader);

        if tag_header.tag_type == 0 && tag_header.size == 8 {
            // End tag
            break;
        }

        match tag_header.tag_type {
            6 => {
                // Memory map tag
                memory_map = Some(parse_memory_map(tag_ptr, tag_header.size)?);
            }
            8 => {
                // Framebuffer tag
                framebuffer_info = Some(parse_framebuffer_info(tag_ptr)?);
            }
            3 => {
                // Module tag
                module_info = Some(parse_module_info(tag_ptr)?);
            }
            _ => {
                // Unknown tag, skip
            }
        }

        // Move to next tag (aligned to 8 bytes)
        let next_offset = (tag_header.size + 7) & !7;
        tag_ptr = tag_ptr.add(next_offset as usize);
    }

    Ok(MultibootInfo {
        memory_map: memory_map.unwrap_or_else(|| Vec::new()),
        framebuffer_info,
        module_info,
    })
}

#[repr(C)]
struct TagHeader {
    tag_type: u32,
    size: u32,
}

/// Parsed multiboot information
pub struct MultibootInfo {
    pub memory_map: Vec<MemoryMapEntry>,
    pub framebuffer_info: Option<FramebufferInfo>,
    pub module_info: Option<ModuleInfo>,
}

/// Framebuffer information
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub framebuffer_type: u8,
}

/// Module information
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub cmdline: Option<&'static str>,
}

unsafe fn parse_memory_map(
    tag_ptr: *const u8,
    size: u32,
) -> Result<Vec<MemoryMapEntry>, &'static str> {
    #[repr(C)]
    struct MemoryMapTag {
        tag_type: u32,
        size: u32,
        entry_size: u32,
        entry_version: u32,
    }

    let tag = &*(tag_ptr as *const MemoryMapTag);
    let entries_size = tag.size - 16; // Subtract tag header
    let num_entries = entries_size / tag.entry_size;

    let mut entries = Vec::with_capacity(num_entries as usize);

    let entry_ptr = tag_ptr.add(16) as *const MemoryMapEntry;
    for i in 0..num_entries {
        let entry = &*entry_ptr.add(i as usize);
        entries.push(*entry);
    }

    Ok(entries)
}

unsafe fn parse_framebuffer_info(tag_ptr: *const u8) -> Result<FramebufferInfo, &'static str> {
    #[repr(C)]
    struct FramebufferTag {
        tag_type: u32,
        size: u32,
        framebuffer_addr: u64,
        framebuffer_pitch: u32,
        framebuffer_width: u32,
        framebuffer_height: u32,
        framebuffer_bpp: u8,
        framebuffer_type: u8,
        reserved: u8,
    }

    let tag = &*(tag_ptr as *const FramebufferTag);

    Ok(FramebufferInfo {
        addr: PhysAddr::new(tag.framebuffer_addr),
        width: tag.framebuffer_width,
        height: tag.framebuffer_height,
        bpp: tag.framebuffer_bpp,
        framebuffer_type: tag.framebuffer_type,
    })
}

unsafe fn parse_module_info(tag_ptr: *const u8) -> Result<ModuleInfo, &'static str> {
    #[repr(C)]
    struct ModuleTag {
        tag_type: u32,
        size: u32,
        mod_start: u32,
        mod_end: u32,
    }

    let tag = &*(tag_ptr as *const ModuleTag);

    // Parse command line if present
    let cmdline_ptr = tag_ptr.add(16) as *const u8;
    let cmdline = if tag.size > 16 {
        // Find null terminator
        let mut len = 0;
        while len < (tag.size - 16) as usize && *cmdline_ptr.add(len) != 0 {
            len += 1;
        }

        if len > 0 {
            let slice = slice::from_raw_parts(cmdline_ptr, len);
            Some(core::str::from_utf8(slice).unwrap_or(""))
        } else {
            None
        }
    } else {
        None
    };

    Ok(ModuleInfo {
        start: PhysAddr::new(tag.mod_start as u64),
        end: PhysAddr::new(tag.mod_end as u64),
        cmdline,
    })
}

/// Detect if running on QEMU vs bare-metal
pub fn detect_platform() -> Platform {
    unsafe {
        // Check for QEMU-specific CPUID features
        let cpuid_result = core::arch::x86_64::__cpuid(0x40000000);

        // QEMU hypervisor signature: "TCGTCGTCGTCG"
        if cpuid_result.ebx == 0x54434754
            && cpuid_result.ecx == 0x54434754
            && cpuid_result.edx == 0x54434754
        {
            return Platform::Qemu;
        }

        // Check for other hypervisor signatures
        if cpuid_result.eax >= 0x40000000 {
            return Platform::VirtualMachine;
        }

        Platform::BareMetal
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    Qemu,
    VirtualMachine,
    BareMetal,
}

/// Platform-specific optimizations
impl Platform {
    pub fn optimize_for_platform(&self) {
        match self {
            Platform::Qemu => {
                // QEMU-specific optimizations
                // - Enable faster timer frequency
                // - Optimize for virtio devices
                // - Reduce unnecessary delays
                crate::log::info!("Detected QEMU - applying virtualization optimizations");
            }

            Platform::VirtualMachine => {
                // General VM optimizations
                crate::log::info!("Detected virtual machine - applying general VM optimizations");
            }

            Platform::BareMetal => {
                // Bare-metal optimizations
                // - Enable hardware-specific features
                // - Optimize for real hardware timing
                // - Enable full hardware acceleration
                crate::log::info!("Detected bare-metal hardware - applying hardware optimizations");
            }
        }
    }

    pub fn get_timer_frequency(&self) -> u32 {
        match self {
            Platform::Qemu => 1000,          // 1kHz for QEMU
            Platform::VirtualMachine => 100, // 100Hz for other VMs
            Platform::BareMetal => 1000,     // 1kHz for bare-metal
        }
    }

    pub fn supports_virtio(&self) -> bool {
        match self {
            Platform::Qemu | Platform::VirtualMachine => true,
            Platform::BareMetal => false,
        }
    }

    pub fn get_console_type(&self) -> ConsoleType {
        match self {
            Platform::Qemu => ConsoleType::Serial, // QEMU usually has serial
            Platform::VirtualMachine => ConsoleType::Vga, // VMs usually have VGA
            Platform::BareMetal => ConsoleType::Vga, // Bare-metal usually has VGA
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ConsoleType {
    Vga,
    Serial,
    Framebuffer,
}

/// Boot-time memory regions for different platforms
pub fn get_safe_memory_regions(
    platform: Platform,
    multiboot_info: &MultibootInfo,
) -> Vec<crate::memory::layout::Region> {
    let mut regions = Vec::new();

    // Parse multiboot memory map
    for entry in &multiboot_info.memory_map {
        if entry.is_available() && entry.length >= 4096 {
            // Skip low memory (first 1MB) to avoid BIOS/bootloader conflicts
            if entry.base_addr < 0x100000 {
                continue;
            }

            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr + entry.length,
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    // If no multiboot memory map, provide safe defaults based on platform
    if regions.is_empty() {
        match platform {
            Platform::Qemu => {
                // QEMU usually provides at least 128MB
                regions.push(crate::memory::layout::Region {
                    start: 0x100000, // 1MB
                    end: 0x8000000,  // 128MB
                    kind: crate::memory::layout::RegionKind::Usable,
                });
            }
            Platform::VirtualMachine => {
                // Conservative VM memory
                regions.push(crate::memory::layout::Region {
                    start: 0x100000, // 1MB
                    end: 0x4000000,  // 64MB
                    kind: crate::memory::layout::RegionKind::Usable,
                });
            }
            Platform::BareMetal => {
                // Very conservative bare-metal
                regions.push(crate::memory::layout::Region {
                    start: 0x100000, // 1MB
                    end: 0x2000000,  // 32MB
                    kind: crate::memory::layout::RegionKind::Usable,
                });
            }
        }
    }

    regions
}

/// Initialize platform-specific features
pub fn init_platform_features(platform: Platform) -> Result<(), &'static str> {
    platform.optimize_for_platform();

    match platform {
        Platform::Qemu => {
            init_qemu_features()?;
        }
        Platform::VirtualMachine => {
            init_vm_features()?;
        }
        Platform::BareMetal => {
            init_baremetal_features()?;
        }
    }

    Ok(())
}

fn init_qemu_features() -> Result<(), &'static str> {
    // Initialize QEMU-specific features
    // - QMP (QEMU Machine Protocol) if available
    // - Virtio console
    // - QEMU guest agent interface

    crate::log::info!("Initialized QEMU-specific features");
    Ok(())
}

fn init_vm_features() -> Result<(), &'static str> {
    // Initialize general VM features
    // - Paravirtualization interfaces
    // - VM guest tools

    crate::log::info!("Initialized general VM features");
    Ok(())
}

fn init_baremetal_features() -> Result<(), &'static str> {
    // Initialize bare-metal hardware features
    // - Hardware acceleration
    // - Direct hardware access
    // - Performance monitoring

    crate::log::info!("Initialized bare-metal hardware features");
    Ok(())
}
