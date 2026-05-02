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

use super::intent::SwitchIntent;
use super::lease::SwitchLease;
use super::outcome::{SwitchError, SwitchOutcome};
use crate::process::core::api::current_pid;
use crate::process::scheduler::preemption::{perform_yield_inline, preempt_current_process};

pub(super) fn interrupts_enabled() -> bool {
    crate::arch::x86_64::cpu::interrupts_enabled()
}

pub(super) fn perform(
    _lease: SwitchLease,
    intent: SwitchIntent,
) -> Result<SwitchOutcome, SwitchError> {
    if current_pid().is_none() {
        return Err(SwitchError::NoCurrentTask);
    }
    match intent {
        SwitchIntent::Preempt => preempt_current_process(),
        SwitchIntent::Yield => perform_yield_inline(),
    }
    Ok(SwitchOutcome::Returned)
}
