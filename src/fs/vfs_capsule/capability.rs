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

use super::error::VfsCapsuleError;
use crate::services::caps::{has_capability, CAP_VFS};

// Single authority gate. Caller pid is read from the kernel's process
// accounting and embedded in every request payload's first 4 bytes
// — never read from caller-supplied data.
pub(super) fn gate_caller() -> Result<u32, VfsCapsuleError> {
    let pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return Err(VfsCapsuleError::NoCallerPid),
    };
    if !has_capability(pid, CAP_VFS) {
        return Err(VfsCapsuleError::AccessDenied);
    }
    Ok(pid)
}
