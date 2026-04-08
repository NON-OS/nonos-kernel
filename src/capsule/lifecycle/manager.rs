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

use crate::capsule::{self, CapsuleId, CapsuleState, metrics, registry};
use super::{hooks, cleanup};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError { NotFound, InvalidState, AlreadyRunning, Faulted }

pub fn start(id: CapsuleId) -> Result<u64, LifecycleError> {
    let capsule = registry::get(id).ok_or(LifecycleError::NotFound)?;
    if capsule.state != CapsuleState::Loaded { return Err(LifecycleError::InvalidState); }
    hooks::on_start(id);
    metrics::collector::register(id);
    crate::ipc::capsule::register(id);
    registry::set_state(id, CapsuleState::Running);
    Ok(capsule.pid.unwrap_or(0))
}

pub fn suspend(id: CapsuleId) -> Result<(), LifecycleError> {
    let capsule = registry::get(id).ok_or(LifecycleError::NotFound)?;
    if capsule.state != CapsuleState::Running { return Err(LifecycleError::InvalidState); }
    hooks::on_suspend(id);
    registry::set_state(id, CapsuleState::Suspended);
    Ok(())
}

pub fn resume(id: CapsuleId) -> Result<(), LifecycleError> {
    let capsule = registry::get(id).ok_or(LifecycleError::NotFound)?;
    if capsule.state != CapsuleState::Suspended { return Err(LifecycleError::InvalidState); }
    hooks::on_resume(id);
    registry::set_state(id, CapsuleState::Running);
    Ok(())
}

pub fn terminate(id: CapsuleId, code: i32) -> Result<(), LifecycleError> {
    let capsule = registry::get(id).ok_or(LifecycleError::NotFound)?;
    match capsule.state {
        CapsuleState::Exited(_) | CapsuleState::Faulted => return Err(LifecycleError::InvalidState),
        _ => {}
    }
    hooks::on_exit(id, code);
    crate::ipc::capsule::unregister(id);
    metrics::collector::unregister(id, false);
    registry::set_state(id, CapsuleState::Exited(code));
    cleanup::cleanup_capsule(id);
    Ok(())
}

pub fn fault(id: CapsuleId) -> Result<(), LifecycleError> {
    hooks::on_fault(id);
    crate::ipc::capsule::unregister(id);
    metrics::collector::unregister(id, true);
    registry::set_state(id, CapsuleState::Faulted);
    cleanup::cleanup_capsule(id);
    Ok(())
}
