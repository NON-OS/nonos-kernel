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

use super::service::{set_pid, update_state, ServiceId, ServiceState, SERVICE_REGISTRY};
use crate::process::core::{create_process, Pid, Priority, ProcessState};

pub fn spawn_init() -> Result<Pid, SpawnError> {
    create_process("init", ProcessState::Ready, Priority::High).map_err(|_| SpawnError::Failed)
}

pub fn spawn_service(id: ServiceId) -> Result<Pid, SpawnError> {
    let name = {
        let reg = SERVICE_REGISTRY.lock();
        let svc = reg.get(id as usize).ok_or(SpawnError::NotFound)?;
        if svc.state != ServiceState::Registered && svc.state != ServiceState::Stopped {
            return Err(SpawnError::InvalidState);
        }
        svc.name.clone()
    };

    update_state(id, ServiceState::Starting);
    let pid = create_process(&name, ProcessState::Ready, Priority::Normal)
        .map_err(|_| SpawnError::Failed)?;
    set_pid(id, pid);
    update_state(id, ServiceState::Running);
    Ok(pid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    NotFound,
    InvalidState,
    Failed,
}
