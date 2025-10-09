//! Programmable Interval Timer (PIT) Support

/// Initialize PIT for periodic interrupts
pub fn init_pit(freq_hz: u32) {
    let divisor = 1193182 / freq_hz;
    unsafe {
        crate::arch::x86_64::port::outb(0x43, 0x36);
        crate::arch::x86_64::port::outb(0x40, (divisor & 0xFF) as u8);
        crate::arch::x86_64::port::outb(0x40, ((divisor >> 8) & 0xFF) as u8);
    }
}

/// Sleep using PIT (busy wait)
pub fn pit_sleep(ms: u64) {
    let start = super::nonos_timer::now_ms();
    while super::nonos_timer::now_ms() - start < ms {
        unsafe { core::arch::asm!("pause"); }
    }
}
