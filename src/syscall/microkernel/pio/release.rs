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

//! `MkPioRelease`. Drop a single grant the caller holds. The
//! capsule-exit and device-release paths use broker-internal
//! drains; this syscall is the explicit holder release.

use super::errno::errno_for;
use crate::hardware::broker::PioError;
use crate::process::current_pid;
use crate::syscall::microkernel::errnos::{ERRNO_INVAL, ERRNO_PERM};

pub fn sys_pio_release(grant_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    match crate::hardware::broker::pio_release_grant(pid, grant_id) {
        Ok(()) => 0,
        Err(PioError::NotHolder) => ERRNO_PERM,
        Err(PioError::UnknownGrant) => ERRNO_INVAL,
        Err(e) => errno_for(e),
    }
}
