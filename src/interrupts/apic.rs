//! Advanced Programmable Interrupt Controller (APIC) Support
//!
//! For modern systems that support APIC instead of PIC

/// Initialize APIC (if available)
pub fn init() -> bool {
    // Check CPUID for APIC support
    unsafe {
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        
        // Check APIC feature flag (bit 9 of EDX)
        if (cpuid_result.edx & (1 << 9)) == 0 {
            crate::log_warn!("APIC not supported by CPU");
            return false;
        }
        
        // Read APIC base MSR (MSR 0x1B)
        let mut apic_base_msr = x86_64::registers::model_specific::Msr::new(0x1B);
        let apic_base = apic_base_msr.read();
        
        // Check if APIC is globally enabled (bit 11)
        if (apic_base & (1 << 11)) == 0 {
            // Enable APIC globally
            apic_base_msr.write(apic_base | (1 << 11));
        }
        
        // Get APIC base address (bits 12-35, shifted by 12)
        let apic_addr = (apic_base & 0xFFFFF000) as u64;
        
        // Enable APIC by writing to Spurious Interrupt Vector Register
        let sivr_addr = (apic_addr + 0xF0) as *mut u32;
        let sivr_value = core::ptr::read_volatile(sivr_addr);
        core::ptr::write_volatile(sivr_addr, sivr_value | (1 << 8)); // Set APIC enable bit
        
        // Set up Local APIC Timer for periodic interrupts
        let timer_lvt_addr = (apic_addr + 0x320) as *mut u32;
        core::ptr::write_volatile(timer_lvt_addr, 32 | (1 << 17)); // Vector 32, periodic mode
        
        // Set timer initial count
        let timer_initial_addr = (apic_addr + 0x380) as *mut u32;
        core::ptr::write_volatile(timer_initial_addr, 1000000); // 1M ticks
        
        // Set timer divide configuration
        let timer_dcr_addr = (apic_addr + 0x3E0) as *mut u32;
        core::ptr::write_volatile(timer_dcr_addr, 0x3); // Divide by 16
        
        crate::log_info!("Local APIC initialized at address: {:#x}", apic_addr);
        true
    }
}

/// Check if APIC is available
pub fn is_available() -> bool {
    unsafe {
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        (cpuid_result.edx & (1 << 9)) != 0
    }
}

/// Get APIC base address
pub fn get_apic_base() -> u64 {
    unsafe {
        let apic_base_msr = x86_64::registers::model_specific::Msr::new(0x1B);
        apic_base_msr.read() & 0xFFFFF000
    }
}