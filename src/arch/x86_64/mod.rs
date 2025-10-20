//! x86_64 Architecture Support

pub mod nonos_acpi;
pub mod nonos_cpu;
pub mod nonos_boot;
pub mod nonos_gdt;
pub mod nonos_idt;
pub mod nonos_multiboot;
pub mod nonos_pci;
pub mod nonos_serial;
pub mod nonos_smm;
pub mod nonos_syscall;
pub mod nonos_uefi;
pub mod nonos_vga;

pub mod interrupt {
    pub mod nonos_apic;
    pub mod nonos_ioapic;
    pub mod nonos_pic_legacy;

    pub use nonos_apic as apic;
    // pub use nonos_ioapic as ioapic;
    // pub use nonos_pic_legacy as pic_legacy;
}

pub use x86_64::structures::idt::InterruptStackFrame;

pub mod keyboard;

// pub use nonos_acpi as acpi;
// pub use nonos_boot as boot;
pub use nonos_cpu as cpu;
pub use nonos_gdt as gdt;
pub use nonos_idt as idt;
// pub use nonos_multiboot as multiboot;
pub use nonos_pci as pci;
pub use nonos_serial as serial;
// pub use nonos_smm as smm;
pub use nonos_syscall as syscall;
// pub use nonos_uefi as uefi;
pub use nonos_vga as vga;

/// Port I/O operations for x86_64
pub mod port_io {
    #[inline(always)]
    pub unsafe fn outb(port: u16, data: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") data, options(nostack, preserves_flags));
    }

    #[inline(always)]
    pub unsafe fn inb(port: u16) -> u8 {
        let mut data: u8;
        core::arch::asm!("in al, dx", out("al") data, in("dx") port, options(nostack, preserves_flags));
        data
    }

    #[inline(always)]
    pub unsafe fn outw(port: u16, data: u16) {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") data, options(nostack, preserves_flags));
    }

    #[inline(always)]
    pub unsafe fn inw(port: u16) -> u16 {
        let mut data: u16;
        core::arch::asm!("in ax, dx", out("ax") data, in("dx") port, options(nostack, preserves_flags));
        data
    }

    #[inline(always)]
    pub unsafe fn outl(port: u16, data: u32) {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") data, options(nostack, preserves_flags));
    }

    #[inline(always)]
    pub unsafe fn inl(port: u16) -> u32 {
        let mut data: u32;
        core::arch::asm!("in eax, dx", out("eax") data, in("dx") port, options(nostack, preserves_flags));
        data
    }
}

pub mod time {
    pub mod nonos_timer;
    pub mod tsc;
    pub mod pit;
    pub mod hpet;
    pub mod rtc;

    pub use nonos_timer as timer;
    pub use tsc::rdtsc as tsc_now;

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

pub mod delay {
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

pub mod framebuffer {
    #[derive(Clone, Copy)]
    pub struct FbInfo {
        pub ptr: usize,
        pub width: u32,
        pub height: u32,
        pub stride: u32,
    }

    pub fn probe() -> Option<FbInfo> {
        None
    }
}

pub mod font8x16 {
    pub fn glyph(_c: u8) -> &'static [u8; 16] {
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

pub fn set_task_context(_task_id: u32) {}

pub fn restore_kernel_context() {}

pub async fn hlt_sleep_ms(ms: u64) {
    for _ in 0..ms {
        unsafe {
            x86_64::instructions::hlt();
        }
    }
}
