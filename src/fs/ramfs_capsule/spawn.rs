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

use core::sync::atomic::Ordering;

use super::client::REPLY_INBOX;
use super::embed::RAMFS_ELF;
use super::state;
use crate::capabilities::Capability;
use crate::elf::loader::load_elf_executable;
use crate::ipc::nonos_inbox;
use crate::kernel_core::process_spawn::{allocate_service_stack, setup_initial_context};
use crate::memory::paging::manager::create_address_space;
use crate::process::core::{create_process, Priority, ProcessState};
use crate::process::with_process_mut;
use crate::services::registry::register_endpoint;

const SERVICE_NAME: &str = "ramfs";
const SERVICE_PORT: u32 = 4096;
const REPLY_PORT: u32 = 4097;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    FeatureDisabled,
    ElfLoad,
    ProcessCreation,
    AddressSpace,
    EndpointCollision,
}

pub fn spawn_ramfs_capsule() -> Result<(), SpawnError> {
    if RAMFS_ELF.is_empty() {
        return Err(SpawnError::FeatureDisabled);
    }
    nonos_inbox::register_inbox(REPLY_INBOX);
    register_endpoint(REPLY_INBOX, REPLY_PORT, 0, 0).map_err(|_| SpawnError::EndpointCollision)?;

    let image = load_elf_executable(RAMFS_ELF).map_err(|_| SpawnError::ElfLoad)?;
    let entry = image.entry_point.as_u64();

    let pid = create_process(SERVICE_NAME, ProcessState::Ready, Priority::Normal)
        .map_err(|_| SpawnError::ProcessCreation)?;
    create_address_space(pid).map_err(|_| SpawnError::AddressSpace)?;

    let caps_bits = Capability::IPC.bit() | Capability::Memory.bit() | Capability::Crypto.bit();
    install_caps(pid, caps_bits);

    let stack_top = allocate_service_stack(pid);
    setup_initial_context(pid, entry, stack_top);

    register_endpoint(SERVICE_NAME, SERVICE_PORT, pid, caps_bits)
        .map_err(|_| SpawnError::EndpointCollision)?;

    crate::sched::add_to_run_queue(pid);
    state::set_alive(pid);
    Ok(())
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
