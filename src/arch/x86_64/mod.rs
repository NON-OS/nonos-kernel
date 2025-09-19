//! x86_64 Architecture Support

pub mod acpi;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod gdt_simple;
pub mod idt;
pub mod idt_simple;
pub mod multiboot;
pub mod pci;
pub mod serial;
pub mod smm;
pub mod syscall;
pub mod uefi;
pub mod vga;

pub mod interrupt {
    pub mod apic;
    pub mod ioapic;
    pub mod pic_legacy;
}

/// Re-export interrupt stack frame
pub use x86_64::structures::idt::InterruptStackFrame;

pub mod keyboard;

pub mod time {
    pub mod timer;
    
    /// Get current TSC value
    #[inline(always)]
    pub fn get_tsc() -> u64 {
        unsafe {
            let mut high: u32;
            let mut low: u32;
            core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
            ((high as u64) << 32) | (low as u64)
        }
    }
}

/// Hardware delay functions
pub mod delay {
    /// Delay for milliseconds using TSC
    pub fn delay_ms(ms: u64) {
        let freq = 2_500_000_000; // 2.5 GHz estimate
        let cycles = (ms * freq) / 1000;
        let start = super::time::get_tsc();
        loop {
            if super::time::get_tsc() - start >= cycles {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

// Port I/O utilities
pub mod port {
    #[inline(always)]
    pub unsafe fn inb(port: u16) -> u8 {
        let value: u8;
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }
    
    #[inline(always)]
    pub unsafe fn outb(port: u16, value: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
    
    #[inline(always)]
    pub unsafe fn inw(port: u16) -> u16 {
        let value: u16;
        core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }
    
    #[inline(always)]
    pub unsafe fn outw(port: u16, value: u16) {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
    }
    
    #[inline(always)]
    pub unsafe fn inl(port: u16) -> u32 {
        let value: u32;
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }
    
    #[inline(always)]
    pub unsafe fn outl(port: u16, value: u32) {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

// Framebuffer support stub
pub mod framebuffer {
    #[derive(Clone, Copy)]
    pub struct FbInfo {
        pub ptr: usize,
        pub width: u32,
        pub height: u32,
        pub stride: u32,
    }
    
    pub fn probe() -> Option<FbInfo> {
        None // Would be populated from bootloader info
    }
}

// Font support for framebuffer console
pub mod font8x16 {
    pub fn glyph(_c: u8) -> &'static [u8; 16] {
        // Simplified: return a blank glyph
        &[0; 16]
    }
}

pub fn halt() {
    unsafe {
        core::arch::asm!("hlt");
    }
}

pub fn clear_cpu_caches() {
    unsafe {
        core::arch::asm!("wbinvd");
    }
}

pub fn flush_tlb() {
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

pub fn set_task_context(task_id: u32) {
    // Set task context for switching
}

pub fn restore_kernel_context() {
    // Restore kernel context
}

/// Sleep for specified milliseconds using HLT instruction
pub async fn hlt_sleep_ms(ms: u64) {
    // In a real implementation, this would use a timer
    // For compilation, provide a stub that yields
    for _ in 0..ms {
        unsafe {
            x86_64::instructions::hlt();
        }
    }
}
