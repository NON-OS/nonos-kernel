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

use super::backend;
use super::intent::SwitchIntent;
use super::lease::SwitchLease;
use super::outcome::{SwitchError, SwitchOutcome};

/// Single contract entry. Mints the lease, then defers to the per-arch
/// backend. On success the call returns once the caller's task is
/// re-scheduled and resumes here. The two scheduler-internal callers
/// (timer preemption and voluntary yield) both route through here; the
/// underlying scheduler primitives are no longer reachable as a public
/// path.
pub fn switch(intent: SwitchIntent) -> Result<SwitchOutcome, SwitchError> {
    let lease = SwitchLease::acquire().ok_or(SwitchError::InterruptsEnabled)?;
    backend::perform(lease, intent)
}
