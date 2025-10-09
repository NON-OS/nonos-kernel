//! High Precision Event Timer (HPET) Support

pub fn detect_hpet() -> Option<u64> {
    // TODO: Add ACPI table search for HPET base address
    const HPET_DEFAULT_BASE: u64 = 0xFED00000;
    // Try default and scan range for HPET register validity
    // See nonos_timer.rs for validation logic
    if super::nonos_timer::is_valid_hpet_base(HPET_DEFAULT_BASE) {
        Some(HPET_DEFAULT_BASE)
    } else {
        None
    }
}

pub fn read_hpet_counter(base: u64) -> u64 {
    unsafe { core::ptr::read_volatile((base + 0xF0) as *const u64) }
}
