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

// Microkernel runtime: init bootstrap and the proof_io capsule
// launcher. These are the only userspace-side modules the active
// microkernel build references. Real userland capsules (ramfs, keyring)
// live under `userland/<name>/` and are spawned through their own
// kernel-side mirrors (`src/fs/ramfs_capsule`,
// `src/security/keyring_capsule`).
pub mod capsule_proof_io;
pub mod init;

pub use init::run_init;

// Legacy kernel-resident `*_service` wrappers. Off in every microkernel
// profile. They are not real userspace; they are kernel threads in PCB
// clothing. Migration to real userland capsules is the M-phase work.
#[cfg(feature = "nonos-legacy-tree")]
pub mod aes_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod agents_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod apps_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod audio_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod blake3_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod capsule_wallpaper;
#[cfg(feature = "nonos-legacy-tree")]
pub mod chacha_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod crypto_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod dilithium_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod display_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod drivers;
#[cfg(feature = "nonos-legacy-tree")]
pub mod ed25519_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod entropy_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod gpu_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod groth16_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod input_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod kworker_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod kyber_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod net_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod netmgr_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod plonk_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod secp256k1_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod service_runner;
#[cfg(feature = "nonos-legacy-tree")]
pub mod sha3_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod shell_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod softirq_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod storage_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod tls_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod udev_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod vfs_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod wallet_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zk_service;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zkprover_service;

#[cfg(feature = "nonos-legacy-tree")]
pub use aes_service::run_aes_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use agents_service::run_agents_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use apps_service::run_apps_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use audio_service::run_audio_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use blake3_service::run_blake3_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use chacha_service::run_chacha_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use crypto_service::run_crypto_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use dilithium_service::run_dilithium_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use display_service::run_display_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use drivers::run_driver_manager;
#[cfg(feature = "nonos-legacy-tree")]
pub use ed25519_service::run_ed25519_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use entropy_service::run_entropy_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use gpu_service::run_gpu_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use groth16_service::run_groth16_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use input_service::run_input_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use kworker_service::run_kworker_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use kyber_service::run_kyber_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use net_service::run_net_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use netmgr_service::run_netmgr_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use plonk_service::run_plonk_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use secp256k1_service::run_secp256k1_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use service_runner::run_service_by_name;
#[cfg(feature = "nonos-legacy-tree")]
pub use sha3_service::run_sha3_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use shell_service::run_shell_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use softirq_service::run_softirq_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use storage_service::run_storage_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use tls_service::run_tls_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use udev_service::run_udev_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use vfs_service::run_vfs_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use wallet_service::run_wallet_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use zk_service::run_zk_service;
#[cfg(feature = "nonos-legacy-tree")]
pub use zkprover_service::run_zkprover_service;

#[cfg(test)]
pub mod tests;
