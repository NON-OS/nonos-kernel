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

use super::supervisor::init_loop;
use crate::sys::boot_log;

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");
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
    #[cfg(feature = "nonos-entropy-smoketest")]
    {
        if let Some(pid) = crate::process::current_pid() {
            crate::syscall::microkernel::capability::grant_caps_internal(
                pid,
                crate::services::caps::CAP_ENTROPY,
            );
        }
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::security::entropy_capsule::smoketest::run();
    }
    #[cfg(feature = "nonos-crypto-hash-smoketest")]
    {
        if let Some(pid) = crate::process::current_pid() {
            crate::syscall::microkernel::capability::grant_caps_internal(
                pid,
                crate::services::caps::CAP_CRYPTO,
            );
        }
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::security::crypto_capsule::smoketest::run();
    }
    #[cfg(feature = "nonos-vfs-smoketest")]
    {
        if let Some(pid) = crate::process::current_pid() {
            crate::syscall::microkernel::capability::grant_caps_internal(
                pid,
                crate::services::caps::CAP_VFS,
            );
        }
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::fs::vfs_capsule::smoketest::run();
    }

    boot_log::ok("INIT", "Capsules spawned");
    lower_init_priority();
    for _ in 0..100 {
        crate::sched::yield_now();
    }
    // Replaces the init image with the proof binary and transfers to
    // CPL=3; control does not return here on success.
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

// Feature-off or failed spawn leaves the capsule state dead; IPC fails closed.
fn spawn_ramfs_capsule() {
    use crate::fs::ramfs_capsule;
    use crate::services::lifecycle;
    match ramfs_capsule::spawn_ramfs_capsule() {
        Ok(()) => {
            boot_log::ok("RAMFS", "capsule spawned");
            lifecycle::register(lifecycle::Capsule {
                name: "ramfs",
                state: ramfs_capsule::shared_state(),
            });
        }
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

// Feature-off or failed spawn leaves the capsule state dead; IPC fails closed.
fn spawn_keyring_capsule() {
    use crate::security::keyring_capsule;
    use crate::services::lifecycle;
    match keyring_capsule::spawn_keyring_capsule() {
        Ok(()) => {
            boot_log::ok("KEYRING", "capsule spawned");
            lifecycle::register(lifecycle::Capsule {
                name: "keyring",
                state: keyring_capsule::shared_state(),
            });
        }
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

// Feature-off or failed spawn leaves the capsule state dead; IPC fails closed.
fn spawn_entropy_capsule() {
    use crate::security::entropy_capsule;
    use crate::services::lifecycle;
    match entropy_capsule::spawn_entropy_capsule() {
        Ok(()) => {
            boot_log::ok("ENTROPY", "capsule spawned");
            lifecycle::register(lifecycle::Capsule {
                name: "entropy",
                state: entropy_capsule::shared_state(),
            });
        }
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

// Feature-off or failed spawn leaves the capsule state dead; IPC fails closed.
fn spawn_crypto_capsule() {
    use crate::security::crypto_capsule;
    use crate::services::lifecycle;
    match crypto_capsule::spawn_crypto_capsule() {
        Ok(()) => {
            boot_log::ok("CRYPTO", "capsule spawned");
            lifecycle::register(lifecycle::Capsule {
                name: "crypto",
                state: crypto_capsule::shared_state(),
            });
        }
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

// Feature-off or failed spawn leaves the capsule state dead; IPC fails closed.
fn spawn_vfs_capsule() {
    use crate::fs::vfs_capsule;
    use crate::services::lifecycle;
    match vfs_capsule::spawn_vfs_capsule() {
        Ok(()) => {
            boot_log::ok("VFS", "capsule spawned");
            lifecycle::register(lifecycle::Capsule {
                name: "vfs",
                state: vfs_capsule::shared_state(),
            });
        }
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
