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
use super::power_types::SleepState;

pub fn enter_sleep_state(state: SleepState) -> AcpiResult<()> {
    match state {
        SleepState::S0 => Ok(()),
        _ => Err(AcpiError::PowerStateNotSupported),
    }
}

// S5 enter requires evaluating the _S5 AML object in the DSDT to read
// the SLP_TYPa / SLP_TYPb values. NONOS has no AML interpreter, no
// DSDT walker, and no ACPI-enable handshake against SMI_CMD. Writing
// SLP_EN with a hardcoded SLP_TYP=0 to PM1 has no defined effect, so
// the entry refuses before any side-effecting register write.
//
// When an AML evaluator lands, replace this body with the real PM1
// programming pre-flighted by ACPI enable.
pub fn shutdown() -> AcpiResult<()> {
    Err(AcpiError::PowerStateNotSupported)
}
