// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::ptr;

use super::error::{AcpiError, AcpiResult};
use super::parser;
use super::tables::AddressSpace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SleepState {
    S0 = 0,
    /// S1 - Power on suspend (CPU stops, RAM powered)
    S1 = 1,
    /// S2 - CPU off (similar to S1, CPU context lost)
    S2 = 2,
    /// S3 - Suspend to RAM (STR, standby)
    S3 = 3,
    /// S4 - Suspend to Disk (hibernate)
    S4 = 4,
    /// S5 - Soft Off (mechanical off)
    S5 = 5,
}

impl SleepState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::S0 => "Working (S0)",
            Self::S1 => "Power On Suspend (S1)",
            Self::S2 => "CPU Off (S2)",
            Self::S3 => "Suspend to RAM (S3)",
            Self::S4 => "Suspend to Disk (S4)",
            Self::S5 => "Soft Off (S5)",
        }
    }
}

mod pm1_bits {
    pub(super) const SLP_TYP_SHIFT: u16 = 10;
    pub(super) const SLP_EN: u16 = 1 << 13;
}
/// Transitions the system to the specified ACPI sleep state.
/// S5 causes system shutdown, S3 suspends to RAM, etc.
pub fn enter_sleep_state(state: SleepState) -> AcpiResult<()> {
    match state {
        SleepState::S0 => Ok(()), // Already in S0
        SleepState::S5 => enter_s5(),
        _ => Err(AcpiError::PowerStateNotSupported),
    }
}

/// Enter S5 (soft off) state
fn enter_s5() -> AcpiResult<()> {
    parser::with_data(|data| {
        let pm1a = data.pm1a_control;
        let pm1b = data.pm1b_control;
        let slp_typ = data.slp_typ[5];
        if pm1a == 0 {
            return Err(AcpiError::HardwareAccessFailed);
        }

        let value = pm1_bits::SLP_EN | ((slp_typ as u16) << pm1_bits::SLP_TYP_SHIFT);
        // Write to PM1a_CNT
        unsafe {
            crate::arch::x86_64::port::outw(pm1a as u16, value);
        }

        if pm1b != 0 {
            unsafe {
                crate::arch::x86_64::port::outw(pm1b as u16, value);
            }
        }
        // If we reach here, the system should have powered off
        // but some systems need a small delay
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        Err(AcpiError::PowerStateNotSupported)
    })
    .unwrap_or(Err(AcpiError::NotInitialized))
}
/// Attempts to power off the system using ACPI S5 state.
/// This function does not return on success.
pub fn shutdown() -> AcpiResult<()> {
    enter_sleep_state(SleepState::S5)
}
/// Attempts to reboot using multiple methods:
/// 1. ACPI reset register (if available)
/// 2. Keyboard controller reset
/// 3. Triple fault (last resort)
pub fn reboot() -> AcpiResult<()> {
    if let Some(reset_performed) = parser::with_data(|data| {
        if let Some(ref reset_reg) = data.reset_reg {
            unsafe {
                match AddressSpace::from_u8(reset_reg.address_space) {
                    Some(AddressSpace::SystemIo) => {
                        crate::arch::x86_64::port::outb(
                            reset_reg.address as u16,
                            data.reset_value,
                        );
                        return true;
                    }
                    Some(AddressSpace::SystemMemory) => {
                        ptr::write_volatile(
                            reset_reg.address as *mut u8,
                            data.reset_value,
                        );
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }) {
        if reset_performed {
            for _ in 0..10000 {
                core::hint::spin_loop();
            }
        }
    }

    // Fallback 1: Keyboard controller reset
    unsafe {
        for _ in 0..1000 {
            if crate::arch::x86_64::port::inb(0x64) & 0x02 == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // Send reset command
        crate::arch::x86_64::port::outb(0x64, 0xFE);
    }

    // Give keyboard controller time
    for _ in 0..100000 {
        core::hint::spin_loop();
    }

    // Fallback 2: Triple fault
    unsafe {
        let null_idt: [u8; 6] = [0; 6];
        core::arch::asm!(
            "lidt [{}]",
            "int3",
            in(reg) &null_idt,
            options(noreturn)
        );
    }
}

pub fn is_sleep_state_supported(state: SleepState) -> bool {
    match state {
        SleepState::S0 => true, // Always supported
        SleepState::S5 => {
            parser::with_data(|data| data.pm1a_control != 0).unwrap_or(false)
        }
        _ => {
            false
        }
    }
}

pub fn current_profile() -> Option<super::tables::PmProfile> {
    parser::pm_profile()
}

pub fn is_server() -> bool {
    parser::pm_profile()
        .map(|p| p.is_server())
        .unwrap_or(false)
}

pub fn is_mobile() -> bool {
    parser::pm_profile()
        .map(|p| p.is_mobile())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_state_values() {
        assert_eq!(SleepState::S0 as u8, 0);
        assert_eq!(SleepState::S3 as u8, 3);
        assert_eq!(SleepState::S5 as u8, 5);
    }

    #[test]
    fn test_sleep_state_names() {
        assert_eq!(SleepState::S0.name(), "Working (S0)");
        assert_eq!(SleepState::S5.name(), "Soft Off (S5)");
    }

    #[test]
    fn test_pm1_bits() {
        assert_eq!(pm1_bits::SLP_EN, 1 << 13);
        assert_eq!(pm1_bits::SLP_TYP_SHIFT, 10);
    }
}
