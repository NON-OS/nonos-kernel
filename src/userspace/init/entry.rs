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

use super::service_list::*;
use super::spawner::{spawn_core_services, spawn_driver_services, spawn_services};
use super::supervisor::init_loop;
use crate::sys::boot_log;

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");
    spawn_driver_services(DRIVER_SERVICES);
    for _ in 0..50 {
        crate::sched::yield_now();
    }
    spawn_services(KERNEL_SERVICES);
    for _ in 0..50 {
        crate::sched::yield_now();
    }
    spawn_services(CRYPTO_ENGINE_SERVICES);
    for _ in 0..20 {
        crate::sched::yield_now();
    }
    spawn_services(SIGNATURE_SERVICES);
    for _ in 0..20 {
        crate::sched::yield_now();
    }
    spawn_services(PQ_CRYPTO_SERVICES);
    for _ in 0..20 {
        crate::sched::yield_now();
    }
    spawn_services(ZK_SERVICES);
    for _ in 0..50 {
        crate::sched::yield_now();
    }
    spawn_services(SYSTEM_SERVICES);
    for _ in 0..50 {
        crate::sched::yield_now();
    }
    spawn_ramfs_capsule();
    #[cfg(feature = "nonos-ramfs-smoketest")]
    {
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::fs::ramfs_capsule::smoketest::run();
    }
    spawn_core_services(CORE_SERVICES);
    boot_log::ok("INIT", "Services spawned");
    lower_init_priority();
    for _ in 0..100 {
        crate::sched::yield_now();
    }
    // Run the proof_io capsule once if its feature is on. exec_process
    // replaces the init process's image with the proof binary and
    // transfers to user mode; on _exit, control does not return here.
    crate::userspace::capsule_proof_io::launch();
    init_loop()
}

fn lower_init_priority() {
    use crate::process::core::{Priority, CURRENT_PID, PROCESS_TABLE};
    use core::sync::atomic::Ordering;
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.priority.lock() = Priority::Low;
    }
}

// Spawn the ramfs userland capsule and let it register the "ramfs"
// service endpoint. Failure is logged and discarded — `state::is_alive`
// stays false, so every later /ram open returns `EIO` deterministically
// rather than silently falling back to the in-kernel ramfs.
fn spawn_ramfs_capsule() {
    use crate::fs::ramfs_capsule;
    match ramfs_capsule::spawn_ramfs_capsule() {
        Ok(()) => boot_log::ok("RAMFS", "capsule spawned"),
        Err(e) => boot_log::error(match e {
            ramfs_capsule::SpawnError::FeatureDisabled => {
                "RAMFS: capsule binary not embedded (feature off)"
            }
            ramfs_capsule::SpawnError::ElfLoad => "RAMFS: capsule ELF load failed",
            ramfs_capsule::SpawnError::ProcessCreation => "RAMFS: process creation failed",
            ramfs_capsule::SpawnError::AddressSpace => "RAMFS: address space allocation failed",
            ramfs_capsule::SpawnError::EndpointCollision => {
                "RAMFS: service endpoint registration failed"
            }
        }),
    }
}
