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

use super::error::CryptoCapsuleError;
use crate::services::caps::{has_capability, CAP_CRYPTO};

// All capsule ops require CAP_CRYPTO. The caller pid is read from the
// kernel's process accounting, never from caller-supplied payload.
pub(super) fn gate_hash() -> Result<u32, CryptoCapsuleError> {
    let pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return Err(CryptoCapsuleError::NoCallerPid),
    };
    if !has_capability(pid, CAP_CRYPTO) {
        return Err(CryptoCapsuleError::AccessDenied);
    }
    Ok(pid)
}
