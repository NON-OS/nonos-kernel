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

use super::embed::WALLPAPER_ELF;
use super::error::SpawnError;
use crate::capabilities::Capability;
use crate::elf::loader::load_elf_executable;
use crate::kernel_core::process_spawn::{allocate_service_stack, setup_initial_context};
use crate::memory::paging::manager::create_address_space;
use crate::process::core::{create_process, Priority, ProcessState};
use crate::process::with_process_mut;

const SERVICE_NAME: &str = "wallpaper";

pub fn spawn_wallpaper_capsule() -> Result<(), SpawnError> {
    if WALLPAPER_ELF.is_empty() {
        return Err(SpawnError::FeatureDisabled);
    }

    let image = load_elf_executable(WALLPAPER_ELF).map_err(|_| SpawnError::ElfLoad)?;
    let entry = image.entry_point.as_u64();

    let pid = create_process(SERVICE_NAME, ProcessState::Ready, Priority::Normal)
        .map_err(|_| SpawnError::ProcessCreation)?;
    create_address_space(pid).map_err(|_| SpawnError::AddressSpace)?;

    let caps_bits = Capability::GraphicsDisplayQuery.bit()
        | Capability::GraphicsSurfaceCreate.bit()
        | Capability::GraphicsSurfaceMap.bit()
        | Capability::GraphicsPresent.bit();
    install_caps(pid, caps_bits);

    let stack_top = allocate_service_stack(pid);
    setup_initial_context(pid, entry, stack_top);

    crate::sched::add_to_run_queue(pid);
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
