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
    let entry = get_service_entry(name).ok_or(IsolationError::ProcessCreation)?;
    let priority = if name == "desktop" { Priority::High } else { Priority::Normal };
    let pid = create_process(name, ProcessState::Ready, priority)
        .map_err(|_| IsolationError::ProcessCreation)?;
    let asid = create_address_space(pid).map_err(|_| IsolationError::AddressSpace)?;
    crate::syscall::microkernel::capability::grant_caps_internal(pid, caps);
    let stack_top = allocate_service_stack(pid);
    setup_initial_context(pid, entry as usize as u64, stack_top);
    crate::sched::add_to_run_queue(pid);
    crate::sys::serial::print(b"[SPAWN] ");
    crate::sys::serial::print_str(name);
    crate::sys::serial::print(b" pid=");
    crate::sys::serial::print_dec(pid as u64);
    crate::sys::serial::println(b"");
    Ok(ServiceProcess { pid, asid, caps })
}

pub fn cleanup_service(svc: &ServiceProcess) -> Result<(), IsolationError> {
    cleanup_address_space(svc.asid).map_err(|_| IsolationError::AddressSpace)
}
