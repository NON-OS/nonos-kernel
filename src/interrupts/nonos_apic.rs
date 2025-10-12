//! APIC wrappers.

#![no_std]

use core::sync::atomic::{AtomicBool, Ordering};

static APIC_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize Local APIC/IOAPIC via arch layer fall back is PIC-only.
pub fn init() {
    if apic_arch_init() {
        APIC_ENABLED.store(true, Ordering::SeqCst);
    }
}

#[inline]
pub fn is_enabled() -> bool {
    APIC_ENABLED.load(Ordering::Relaxed)
}

/// Signal end-of-interrupt. 
pub fn eoi() {
    if is_enabled() {
        let _ = apic_arch_eoi();
    }
}

// ---- Arch delegation (optional, returns false if not linked) ----

#[inline]
fn apic_arch_init() -> bool {
    #[cfg(any())]
    {
        crate::arch::x86_64::interrupt::apic::init();
        return true;
    }
    // Try calling.
    false
}

#[inline]
fn apic_arch_eoi() -> bool {
    #[cfg(any())]
    {
        crate::arch::x86_64::interrupt::apic::eoi();
        return true;
    }
    false
}
