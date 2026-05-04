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

#[cfg(feature = "nonos-legacy-tree")]
use super::service_list::*;
#[cfg(feature = "nonos-legacy-tree")]
use super::spawner::{spawn_core_services, spawn_driver_services, spawn_services};
use super::supervisor::init_loop;
use crate::sys::boot_log;

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");

    // Legacy kernel-resident service batches. Off in every microkernel
    // profile. The capsules below are the only things `run_init`
    // launches in microkernel mode.
    #[cfg(feature = "nonos-legacy-tree")]
    {
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
    }

    spawn_ramfs_capsule();
    #[cfg(feature = "nonos-ramfs-smoketest")]
    {
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::fs::ramfs_capsule::smoketest::run();
    }

    spawn_keyring_capsule();
    spawn_entropy_capsule();
    spawn_crypto_capsule();
    spawn_vfs_capsule();
    #[cfg(feature = "nonos-keyring-smoketest")]
    {
        // The smoketest drives client ops gated by CAP_KEYRING. Grant
        // it to whatever pid run_init runs as; production builds never
        // see this grant.
        if let Some(pid) = crate::process::current_pid() {
            crate::syscall::microkernel::capability::grant_caps_internal(
                pid,
                crate::services::caps::CAP_KEYRING,
            );
        }
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::security::keyring_capsule::smoketest::run();
    }

    #[cfg(feature = "nonos-legacy-tree")]
    spawn_core_services(CORE_SERVICES);

    boot_log::ok("INIT", "Capsules spawned");
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

// Spawn the keyring userland capsule. Replaces the old in-kernel
// keyring service entirely; there is no fallback path. Failure is
// logged and discarded; every later keyring client call returns
// KeyringCapsuleError::Dead until a respawn lands.
fn spawn_keyring_capsule() {
    use crate::security::keyring_capsule;
    match keyring_capsule::spawn_keyring_capsule() {
        Ok(()) => boot_log::ok("KEYRING", "capsule spawned"),
        Err(e) => boot_log::error(match e {
            keyring_capsule::SpawnError::FeatureDisabled => {
                "KEYRING: capsule binary not embedded (feature off)"
            }
            keyring_capsule::SpawnError::ElfLoad => "KEYRING: capsule ELF load failed",
            keyring_capsule::SpawnError::ProcessCreation => "KEYRING: process creation failed",
            keyring_capsule::SpawnError::AddressSpace => "KEYRING: address space allocation failed",
            keyring_capsule::SpawnError::EndpointCollision => {
                "KEYRING: service endpoint registration failed"
            }
        }),
    }
}

// Spawn the entropy userland capsule. Failure is logged and discarded;
// every later entropy client call returns `EntropyCapsuleError::Dead`
// until a respawn lands. There is no kernel-side fallback: once the
// capsule is the authority, the missing-capsule case must be observable.
fn spawn_entropy_capsule() {
    use crate::security::entropy_capsule;
    match entropy_capsule::spawn_entropy_capsule() {
        Ok(()) => boot_log::ok("ENTROPY", "capsule spawned"),
        Err(e) => boot_log::error(match e {
            entropy_capsule::SpawnError::FeatureDisabled => {
                "ENTROPY: capsule binary not embedded (feature off)"
            }
            entropy_capsule::SpawnError::ElfLoad => "ENTROPY: capsule ELF load failed",
            entropy_capsule::SpawnError::ProcessCreation => "ENTROPY: process creation failed",
            entropy_capsule::SpawnError::AddressSpace => "ENTROPY: address space allocation failed",
            entropy_capsule::SpawnError::EndpointCollision => {
                "ENTROPY: service endpoint registration failed"
            }
        }),
    }
}

// Spawn the shared crypto userland capsule (BLAKE3 / SHA3-256 today;
// AEAD / sign / PQC fold in as later slices). On failure every client
// call returns `CryptoCapsuleError::Dead`; no kernel-side `*_engine`
// fallback in production paths.
fn spawn_crypto_capsule() {
    use crate::security::crypto_capsule;
    match crypto_capsule::spawn_crypto_capsule() {
        Ok(()) => boot_log::ok("CRYPTO", "capsule spawned"),
        Err(e) => boot_log::error(match e {
            crypto_capsule::SpawnError::FeatureDisabled => {
                "CRYPTO: capsule binary not embedded (feature off)"
            }
            crypto_capsule::SpawnError::ElfLoad => "CRYPTO: capsule ELF load failed",
            crypto_capsule::SpawnError::ProcessCreation => "CRYPTO: process creation failed",
            crypto_capsule::SpawnError::AddressSpace => "CRYPTO: address space allocation failed",
            crypto_capsule::SpawnError::EndpointCollision => {
                "CRYPTO: service endpoint registration failed"
            }
        }),
    }
}

// Spawn the VFS userland capsule (Open / Close / Read / Write / Stat /
// List / HealthCheck). On failure every client call returns
// `VfsCapsuleError::Dead`. No kernel-side `vfs_engine` fallback.
fn spawn_vfs_capsule() {
    use crate::fs::vfs_capsule;
    match vfs_capsule::spawn_vfs_capsule() {
        Ok(()) => boot_log::ok("VFS", "capsule spawned"),
        Err(e) => boot_log::error(match e {
            vfs_capsule::SpawnError::FeatureDisabled => {
                "VFS: capsule binary not embedded (feature off)"
            }
            vfs_capsule::SpawnError::ElfLoad => "VFS: capsule ELF load failed",
            vfs_capsule::SpawnError::ProcessCreation => "VFS: process creation failed",
            vfs_capsule::SpawnError::AddressSpace => "VFS: address space allocation failed",
            vfs_capsule::SpawnError::EndpointCollision => {
                "VFS: service endpoint registration failed"
            }
        }),
    }
}
