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

use crate::process::core::{create_process, ProcessState, Priority};
use crate::memory::paging::manager::{create_address_space, cleanup_address_space};
use super::context::setup_initial_context;
use super::entries::get_service_entry;
use super::stack::allocate_service_stack;
use super::types::{ServiceProcess, IsolationError};

pub fn spawn_isolated_service(name: &str, caps: u64) -> Result<ServiceProcess, IsolationError> {
    crate::sys::serial::println(b"[SPAWN] Getting entry point");
    let entry = get_service_entry(name).ok_or(IsolationError::ProcessCreation)?;

    crate::sys::serial::println(b"[SPAWN] Creating process");
    let pid = create_process(name, ProcessState::Ready, Priority::Normal)
        .map_err(|_| IsolationError::ProcessCreation)?;

    crate::sys::serial::println(b"[SPAWN] Creating address space");
    let asid = create_address_space(pid).map_err(|e| {
        crate::sys::serial::print(b"[SPAWN] ASID failed: ");
        crate::sys::serial::println(e.as_str().as_bytes());
        IsolationError::AddressSpace
    })?;

    crate::sys::serial::println(b"[SPAWN] Granting caps");
    crate::syscall::microkernel::capability::grant_caps_internal(pid, caps);

    crate::sys::serial::println(b"[SPAWN] Setting up context");
    let stack_top = allocate_service_stack(pid);
    setup_initial_context(pid, entry as usize as u64, stack_top);

    crate::sys::serial::println(b"[SPAWN] Adding to run queue");
    crate::sched::add_to_run_queue(pid);

    crate::sys::serial::println(b"[SPAWN] Done");
    Ok(ServiceProcess { pid, asid, caps })
}

pub fn cleanup_service(svc: &ServiceProcess) -> Result<(), IsolationError> {
    cleanup_address_space(svc.asid).map_err(|_| IsolationError::AddressSpace)
}
