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

use spin::Mutex;

use super::state::AntiRollbackState;
use super::types::{RollbackError, VersionState};

pub static ANTI_ROLLBACK: Mutex<AntiRollbackState> = Mutex::new(AntiRollbackState::new());

pub fn init_anti_rollback(tpm_available: bool) -> Result<(), RollbackError> {
    let mut state = ANTI_ROLLBACK.lock();
    state.init(tpm_available)
}

pub fn check_kernel_version(version: u64) -> Result<(), RollbackError> {
    let state = ANTI_ROLLBACK.lock();
    state.check_kernel_version(version)
}

pub fn update_kernel_version(version: u64, timestamp: u64) -> Result<(), RollbackError> {
    let mut state = ANTI_ROLLBACK.lock();
    state.update_kernel_version(version, timestamp)
}

pub fn get_version_state() -> VersionState {
    let state = ANTI_ROLLBACK.lock();
    *state.get_state()
}
