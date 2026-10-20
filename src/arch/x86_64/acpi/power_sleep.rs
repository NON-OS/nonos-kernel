// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::error::{AcpiError, AcpiResult};
use super::hw::port_bus::{busy_wait_us, PortBus};
use super::hw::sleep::{enter_sleep, SleepError, SleepTypes};
use super::parser;
use super::power_types::SleepState;

pub fn enter_sleep_state(state: SleepState) -> AcpiResult<()> {
    match state {
        SleepState::S0 => Ok(()),
        SleepState::S5 => shutdown(),
        // S1..S4 need _PTS, _WAK and a resume path; none exists.
        _ => Err(AcpiError::PowerStateNotSupported),
    }
}

fn wbinvd() {
    // SAFETY: WBINVD writes back and invalidates the caches; it has no
    // memory operands and is legal at CPL 0, where this runs.
    unsafe { core::arch::asm!("wbinvd", options(nostack, preserves_flags)) };
}

/// Enter S5 (soft off).
///
/// SLP_TYPa/b come from the `\_S5` package found at init. The register
/// sequence is ACPICA's (`hw::sleep`): clear the fixed and GPE status bits,
/// disable every GPE, write SLP_TYP to PM1a and PM1b control, then SLP_EN.
/// A hardware-reduced FADT uses SLEEP_CONTROL_REG instead.
///
/// `_PTS(5)` is not run: it is an AML method and the kernel has no AML
/// interpreter. On most firmware it only records the target state for SMM or
/// the EC; the PM1 write itself is what removes power.
///
/// Returns only when the machine is still running afterwards. As ACPICA does
/// for S4/S5, the enable write is repeated once after a wait, for chipsets
/// that miss the first.
pub fn shutdown() -> AcpiResult<()> {
    let (fadt, s5) = parser::with_data(|d| (d.fadt, d.s5)).ok_or(AcpiError::NotInitialized)?;
    let fadt = fadt.ok_or(AcpiError::FadtNotFound)?;
    let s5 = s5.ok_or(AcpiError::PowerStateNotSupported)?;
    let types = SleepTypes { a: s5.slp_typ_a, b: s5.slp_typ_b };

    // SAFETY: CLI only masks maskable interrupts on this CPU; nothing past
    // this point expects to be interrupted.
    unsafe { core::arch::asm!("cli", options(nostack)) };

    let mut bus = PortBus;
    for _ in 0..2 {
        match enter_sleep(&mut bus, &fadt, types, wbinvd) {
            Ok(()) => {}
            Err(SleepError::NoControlRegister) => return Err(AcpiError::PowerStateNotSupported),
            Err(SleepError::WriteFailed) => return Err(AcpiError::HardwareAccessFailed),
        }
        // Power should be gone within milliseconds; give slow boards 3 s.
        busy_wait_us(3_000_000);
    }
    Err(AcpiError::HardwareAccessFailed)
}
