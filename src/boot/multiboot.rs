//! Multiboot2 Header for QEMU/GRUB compatibility
//! This allows the kernel to be loaded directly by multiboot-compliant bootloaders

use core::arch::asm;

/// Get current CPU features using CPUID
pub fn get_cpu_features() -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32; 
    let mut ecx: u32;
    let mut edx: u32;
    
    unsafe {
        // Use a different register and move it to avoid rbx conflicts
        asm!(
            "mov {tmp:e}, ebx",    // Save rbx
            "cpuid",               // Execute CPUID
            "xchg {tmp:e}, ebx",   // Exchange rbx with tmp, getting CPUID result in tmp
            inout("eax") 1u32 => eax,
            out("ecx") ecx,
            out("edx") edx,
            tmp = lateout(reg) ebx,
        );
    }
    
    (eax, ebx, ecx, edx)
}

/// Enable processor features for kernel initialization
pub fn enable_processor_features() {
    // Enable necessary CPU features for kernel operation
    unsafe {
        // Enable SSE and SSE2
        asm!(
            "mov rax, cr0",
            "and rax, ~(1 << 2)",  // Clear CR0.EM (emulation)
            "or rax, (1 << 1)",    // Set CR0.MP (monitor coprocessor)
            "mov cr0, rax",
            "mov rax, cr4",
            "or rax, (3 << 9)",    // Set CR4.OSFXSR and CR4.OSXMMEXCPT
            "mov cr4, rax",
            out("rax") _,
        );
    }
}

/// Multiboot2 magic number
const MULTIBOOT2_MAGIC: u32 = 0x36d76289;

/// Multiboot2 architecture (i386)
const MULTIBOOT2_ARCH: u32 = 0;

/// Multiboot2 header
#[repr(C, align(8))]
struct Multiboot2Header {
    magic: u32,
    architecture: u32,
    header_length: u32,
    checksum: u32,
    
    // End tag
    end_tag_type: u16,
    end_tag_flags: u16,
    end_tag_size: u32,
}

const MULTIBOOT2_HEADER_LENGTH: u32 = core::mem::size_of::<Multiboot2Header>() as u32;
const MULTIBOOT2_CHECKSUM: u32 = (-(MULTIBOOT2_MAGIC as i32 + MULTIBOOT2_ARCH as i32 + MULTIBOOT2_HEADER_LENGTH as i32)) as u32;

#[used]
#[no_mangle]
#[link_section = ".multiboot_header"]
static MULTIBOOT2_HEADER: Multiboot2Header = Multiboot2Header {
    magic: MULTIBOOT2_MAGIC,
    architecture: MULTIBOOT2_ARCH,
    header_length: MULTIBOOT2_HEADER_LENGTH,
    checksum: MULTIBOOT2_CHECKSUM,
    
    // End tag
    end_tag_type: 0,
    end_tag_flags: 0,
    end_tag_size: 8,
};

/// Multiboot2 entry point
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn multiboot2_entry() -> ! {
    core::arch::naked_asm!(
        // Set up a minimal stack
        "mov rsp, {stack}",
        // Jump to Rust entry point
        "call {rust_entry}",
        // Halt if we return
        "cli",
        "hlt",
        stack = const 0x80000, // 512KB stack
        rust_entry = sym crate::kernel_main,
    );
}