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

extern crate alloc;

use alloc::string::String;

use crate::services::registry::lookup_service;
use crate::syscall::microkernel::errnos::{ERRNO_ACCES, ERRNO_NOENT};

// Resolve a syscall `endpoint` argument to the registry name the
// receive path should drain. `0` means "my own per-process inbox";
// anything else must be a registry endpoint the caller owns.
pub(super) fn resolve_for_recv(endpoint: u64, pid: u32) -> Result<String, i64> {
    if endpoint == 0 {
        return Ok(alloc::format!("proc.{}", pid));
    }
    let target = alloc::format!("endpoint.{}", endpoint);
    match lookup_service(&target) {
        None => Err(ERRNO_NOENT),
        Some(ep) if ep.pid == pid => Ok(target),
        Some(_) => Err(ERRNO_ACCES),
    }
}
