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

use super::error::KeyringCapsuleError;
use crate::services::caps::{has_capability, CAP_KEYRING};

// Single authority gate for every keyring capsule operation. The pid
// is read from the kernel's process accounting, never from a
// caller-supplied payload, so payload-carried identity can never be
// trusted into the cap check. Returns the trusted caller pid that
// the client wrappers then embed into the request payload for the
// capsule to enforce per-key ownership.
pub(super) fn gate_caller() -> Result<u32, KeyringCapsuleError> {
    let pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return Err(KeyringCapsuleError::NoCallerPid),
    };
    if !has_capability(pid, CAP_KEYRING) {
        return Err(KeyringCapsuleError::AccessDenied);
    }
    Ok(pid)
}
