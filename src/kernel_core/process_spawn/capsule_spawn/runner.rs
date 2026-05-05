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
use crate::elf::loader::load_elf_executable;
use crate::ipc::nonos_inbox;
use crate::kernel_core::process_spawn::{
    allocate_kernel_stack, allocate_user_stack, setup_initial_user_context,
};
use crate::memory::paging::constants::KERNEL_ASID;
use crate::memory::paging::manager::{switch_address_space, switch_to_process_address_space};
use crate::process::core::{create_process, Priority, ProcessState};
use crate::process::with_process_mut;
use crate::services::registry::register_endpoint;

pub fn spawn(spec: &CapsuleSpec) -> Result<u32, SpawnError> {
    if spec.elf.is_empty() {
        return Err(SpawnError::FeatureDisabled);
    }
    // Reply inbox is kernel-drained — owner=0. Idempotent so a
    // respawn after a capsule death reuses the same queue; stale
    // replies are filtered by the transport's generation re-check.
    nonos_inbox::register_or_get_bootstrap_inbox(spec.reply_inbox);
    register_endpoint(spec.reply_inbox, spec.reply_port, 0, 0)
        .map_err(|_| SpawnError::EndpointCollision)?;

    let pid = create_process(spec.name, ProcessState::Ready, Priority::Normal)
        .map_err(|_| SpawnError::ProcessCreation)?;

    // Capsule-owned recv inbox. Registered here so a kernel client
    // can `try_enqueue_strict` to `proc.{pid}` the moment this
    // function returns; the capsule's own MkIpcRecv path no longer
    // needs to lazy-create it.
    nonos_inbox::register_inbox(&format!("proc.{}", pid), pid)
        .map_err(|_| SpawnError::ProcessCreation)?;

    let entry = load_elf_into_pid(spec.elf, pid, spec.debug_tag)?;

    install_caps(pid, spec.caps_bits);

    let _kernel_stack = allocate_kernel_stack(pid).map_err(|_| SpawnError::AddressSpace)?;
    let user_rsp = allocate_user_stack(pid).map_err(|_| SpawnError::AddressSpace)?;
    setup_initial_user_context(pid, entry, user_rsp).map_err(|_| SpawnError::AddressSpace)?;

    register_endpoint(spec.name, spec.service_port, pid, spec.caps_bits)
        .map_err(|_| SpawnError::EndpointCollision)?;

    crate::sched::add_to_run_queue(pid);
    Ok(pid)
}

// Load the capsule's ELF in its own address space, then return to the
// kernel master AS before any caller-side work happens. Failing to
// switch back is fail-hard: the paging manager has lost a known-good
// asid and continuing in an unknown CR3 corrupts every later capsule
// operation.
fn load_elf_into_pid(
    elf: &'static [u8],
    pid: u32,
    debug_tag: &'static [u8],
) -> Result<u64, SpawnError> {
    switch_to_process_address_space(pid).map_err(|_| SpawnError::AddressSpace)?;
    let load = load_elf_executable(elf).map_err(|err| {
        crate::sys::serial::println(debug_tag);
        crate::sys::serial::println(err.as_str().as_bytes());
        SpawnError::ElfLoad
    });
    if switch_address_space(KERNEL_ASID).is_err() {
        crate::sys::serial::println(b"[FATAL] paging manager lost KERNEL_ASID");
        crate::boot::halt_loop();
    }
    Ok(load?.entry_point.as_u64())
}

fn install_caps(pid: u32, caps_bits: u64) {
    crate::syscall::microkernel::capability::grant_caps_internal(pid, caps_bits);
    let _ = with_process_mut(pid, |pcb| {
        pcb.caps_bits.store(caps_bits, Ordering::SeqCst);
        let mut caps = pcb.caps.lock();
        caps.permitted = caps_bits;
        caps.effective = caps_bits;
        caps.inheritable = caps_bits;
        caps.bounding = caps_bits;
    });
}
