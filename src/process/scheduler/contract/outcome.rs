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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// The backend returned. Whether a different task actually ran is
    /// not observable from the contract today; the scheduler clears its
    /// per-CPU "just-restored" flag inside `preempt_current_process`
    /// before we get control back. Switched/Stayed split lands when
    /// preempt surfaces that flag.
    Returned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchError {
    /// Interrupts were enabled at entry. Switching with IF=1 races the
    /// trap path on the same CPU.
    InterruptsEnabled,
    /// No current task on this CPU to switch out of.
    NoCurrentTask,
}
