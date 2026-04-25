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
use super::parser;
use super::power_types::{pm1_bits, SleepState};

pub fn enter_sleep_state(state: SleepState) -> AcpiResult<()> {
    match state {
        SleepState::S0 => Ok(()),
        SleepState::S5 => enter_s5(),
        _ => Err(AcpiError::PowerStateNotSupported),
    }
}

fn enter_s5() -> AcpiResult<()> {
    parser::with_data(|data| {
        let pm1a = data.pm1a_control;
        let pm1b = data.pm1b_control;
        let slp_typ = data.slp_typ[5];
        if pm1a == 0 {
            return Err(AcpiError::HardwareAccessFailed);
        }
        let value = pm1_bits::SLP_EN | ((slp_typ as u16) << pm1_bits::SLP_TYP_SHIFT);
        unsafe {
            crate::arch::x86_64::port::outw(pm1a as u16, value);
        }
        if pm1b != 0 {
            unsafe {
                crate::arch::x86_64::port::outw(pm1b as u16, value);
            }
        }
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        Err(AcpiError::PowerStateNotSupported)
    })
    .unwrap_or(Err(AcpiError::NotInitialized))
}

pub fn shutdown() -> AcpiResult<()> {
    enter_sleep_state(SleepState::S5)
}
