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

use crate::capsule::{registry, CapsuleId};

#[derive(Debug, Clone)]
pub struct ExecContext {
    pub capsule_id: CapsuleId,
    pub pid: u64,
    pub caps: u64,
    pub mem_limit: u64,
    pub entry: u64,
}

pub fn get_context(pid: u64) -> Option<ExecContext> {
    let id = registry::id_by_pid(pid)?;
    let capsule = registry::get(id)?;
    let sb = registry::get_sandbox(id)?;
    Some(ExecContext {
        capsule_id: id,
        pid: capsule.pid.unwrap_or(pid),
        caps: sb.caps(),
        mem_limit: sb.mem_limit(),
        entry: sb.entry(),
    })
}

pub fn get_capsule_id(pid: u64) -> Option<CapsuleId> {
    registry::id_by_pid(pid)
}

pub fn get_pid(id: CapsuleId) -> Option<u64> {
    registry::get(id)?.pid
}

pub fn is_capsule_process(pid: u64) -> bool {
    registry::id_by_pid(pid).is_some()
}

pub fn has_capability(pid: u64, cap: u64) -> bool {
    registry::sandbox_by_pid(pid).map(|sb| sb.has_cap(cap)).unwrap_or(false)
}

pub fn check_capability(pid: u64, cap: u64) -> Result<(), ()> {
    if has_capability(pid, cap) {
        Ok(())
    } else {
        Err(())
    }
}

pub fn get_mem_used(pid: u64) -> u64 {
    registry::sandbox_by_pid(pid).map(|sb| sb.mem_used()).unwrap_or(0)
}

pub fn get_mem_limit(pid: u64) -> u64 {
    registry::sandbox_by_pid(pid).map(|sb| sb.mem_limit()).unwrap_or(0)
}
