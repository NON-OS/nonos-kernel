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

use alloc::format;
use core::sync::atomic::Ordering;

use super::spec::{CapsuleSpec, SpawnError};
use crate::elf::loader::load_elf_executable_into;
use crate::ipc::nonos_inbox;
use crate::kernel_core::process_spawn::{
    allocate_kernel_stack, allocate_user_stack, setup_initial_user_context,
};
use crate::memory::paging::manager::lookup_asid_for_process;
use crate::process::core::{create_process, Priority, ProcessState};
use crate::process::with_process_mut;
use crate::services::registry::register_endpoint;

pub fn spawn(spec: &CapsuleSpec) -> Result<u32, SpawnError> {
    use crate::sys::serial::println;
    if spec.elf.is_empty() {
        return Err(SpawnError::FeatureDisabled);
    }
    println(b"[SPAWN] inbox+endpoint");
    nonos_inbox::register_or_get_bootstrap_inbox(spec.reply_inbox);
    register_endpoint(spec.reply_inbox, spec.reply_port, 0, 0)
        .map_err(|_| SpawnError::EndpointCollision)?;

    println(b"[SPAWN] create_process");
    let pid = create_process(spec.name, ProcessState::Ready, Priority::Normal)
        .map_err(|_| SpawnError::ProcessCreation)?;

    println(b"[SPAWN] recv inbox");
    nonos_inbox::register_inbox(&format!("proc.{}", pid), pid)
        .map_err(|_| SpawnError::ProcessCreation)?;

    println(b"[SPAWN] elf load");
    let entry = load_elf_into_pid(spec.elf, pid, spec.debug_tag)?;
    println(b"[SPAWN] elf load done");

    install_caps(
        pid,
        spec.caps_bits | crate::capabilities::smoke::debug_grant(),
    );
    println(b"[SPAWN] caps installed");

    let _kernel_stack = allocate_kernel_stack(pid).map_err(|e| {
        println(b"[SPAWN] kstack FAIL");
        let _ = e;
        SpawnError::AddressSpace
    })?;
    println(b"[SPAWN] kstack");
    let user_rsp = allocate_user_stack(pid).map_err(|_| SpawnError::AddressSpace)?;
    println(b"[SPAWN] ustack");
    setup_initial_user_context(pid, entry, user_rsp).map_err(|_| SpawnError::AddressSpace)?;
    println(b"[SPAWN] ucontext");

    register_endpoint(spec.name, spec.service_port, pid, spec.caps_bits)
        .map_err(|_| SpawnError::EndpointCollision)?;
    println(b"[SPAWN] svc endpoint");

    crate::sched::add_to_run_queue(pid);
    println(b"[SPAWN] enqueued");
    Ok(pid)
}

fn load_elf_into_pid(
    elf: &'static [u8],
    pid: u32,
    debug_tag: &'static [u8],
) -> Result<u64, SpawnError> {
    let asid = lookup_asid_for_process(pid).ok_or(SpawnError::AddressSpace)?;
    let load = load_elf_executable_into(elf, asid).map_err(|err| {
        crate::sys::serial::println(debug_tag);
        crate::sys::serial::println(err.as_str().as_bytes());
        SpawnError::ElfLoad
    })?;
    Ok(load.entry_point.as_u64())
}

// `caps_bits` stored on the PCB is the single source of truth. The
// syscall contract decodes it against `crate::capabilities::Capability`.
// Spec authors build the mask from that namespace; this function
// stores it verbatim.
fn install_caps(pid: u32, caps_bits: u64) {
    let _ = with_process_mut(pid, |pcb| {
        pcb.caps_bits.store(caps_bits, Ordering::SeqCst);
    });
}
