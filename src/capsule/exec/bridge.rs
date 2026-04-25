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

use crate::capsule::{lifecycle, registry, CapsuleId, CapsuleState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    NotFound,
    InvalidState,
    SpawnFailed,
    SandboxViolation,
}

pub fn spawn_capsule(id: CapsuleId) -> Result<u64, ExecError> {
    let capsule = registry::get(id).ok_or(ExecError::NotFound)?;
    if capsule.state != CapsuleState::Loaded {
        return Err(ExecError::InvalidState);
    }
    let sb = registry::get_sandbox(id).ok_or(ExecError::NotFound)?;
    // Verify sandbox is ready and has valid entry point
    if sb.state() != crate::capsule::sandbox::SandboxState::Ready {
        return Err(ExecError::InvalidState);
    }
    let entry_point = sb.entry();
    if entry_point == 0 {
        return Err(ExecError::SpawnFailed);
    }
    let name = alloc::format!("capsule:{}", id);
    let pid = crate::process::create_process(
        &name,
        crate::process::ProcessState::Ready,
        crate::process::Priority::Normal,
    )
    .map_err(|_| ExecError::SpawnFailed)?;
    registry::map_pid(pid as u64, id);
    if let Some(c) = registry::get_mut(id) {
        c.pid = Some(pid as u64);
    }
    // Set sandbox to running state
    if let Some(sandbox) = registry::get_sandbox_mut(id) {
        sandbox.set_state(crate::capsule::sandbox::SandboxState::Running);
    }
    lifecycle::manager::start(id).map_err(|_| ExecError::InvalidState)?;
    Ok(pid as u64)
}

pub fn terminate_capsule(id: CapsuleId, code: i32) -> Result<(), ExecError> {
    let capsule = registry::get(id).ok_or(ExecError::NotFound)?;
    if let Some(pid) = capsule.pid {
        let _ = crate::process::control::kill(pid as u32, code);
    }
    lifecycle::manager::terminate(id, code).map_err(|_| ExecError::InvalidState)?;
    Ok(())
}

pub fn handle_capsule_fault(id: CapsuleId) {
    let _ = lifecycle::manager::fault(id);
    if let Some(c) = registry::get(id) {
        if let Some(pid) = c.pid {
            let _ = crate::process::control::kill(pid as u32, -1);
        }
    }
}

pub fn handle_capsule_exit(pid: u64, code: i32) {
    if let Some(id) = registry::id_by_pid(pid) {
        let _ = lifecycle::manager::terminate(id, code);
    }
}

pub fn suspend_capsule(id: CapsuleId) -> Result<(), ExecError> {
    let capsule = registry::get(id).ok_or(ExecError::NotFound)?;
    if let Some(pid) = capsule.pid {
        let _ = crate::process::stop_process(pid as u32);
    }
    lifecycle::manager::suspend(id).map_err(|_| ExecError::InvalidState)?;
    Ok(())
}

pub fn resume_capsule(id: CapsuleId) -> Result<(), ExecError> {
    let capsule = registry::get(id).ok_or(ExecError::NotFound)?;
    if let Some(pid) = capsule.pid {
        let _ = crate::process::resume_process(pid as u32);
    }
    lifecycle::manager::resume(id).map_err(|_| ExecError::InvalidState)?;
    Ok(())
}
