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

use crate::services::registry::lookup_service;
use crate::syscall::microkernel::capability::check_caps_internal;

pub const EACCES: i32 = -13;
pub const ENOENT: i32 = -2;

pub fn kernel_check_ipc_permission(caller_pid: u32, target: &str) -> Result<(), i32> {
    let endpoint = lookup_service(target).ok_or(ENOENT)?;
    if !check_caps_internal(caller_pid, endpoint.caps_required) {
        return Err(EACCES);
    }
    Ok(())
}

pub fn kernel_route_ipc(caller_pid: u32, target: &str, data: &[u8]) -> Result<(), i32> {
    kernel_check_ipc_permission(caller_pid, target)?;
    let msg = crate::ipc::nonos_channel::IpcMessage::new(
        &alloc::format!("proc.{}", caller_pid),
        target,
        data,
    )
    .map_err(|_| -12)?;
    crate::ipc::nonos_inbox::try_enqueue(target, msg).map_err(|_| -11)
}
