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

pub mod aes_service;
pub mod agents_service;
pub mod apps_service;
pub mod audio_service;
pub mod blake3_service;
pub mod capsule_proof_io;
pub mod capsule_wallpaper;
pub mod chacha_service;
pub mod crypto_service;
pub mod dilithium_service;
pub mod display_service;
pub mod drivers;
pub mod ed25519_service;
pub mod entropy_service;
pub mod gpu_service;
pub mod groth16_service;
pub mod init;
pub mod input_service;
pub mod keyring_service;
pub mod kworker_service;
pub mod kyber_service;
pub mod net_service;
pub mod netmgr_service;
pub mod plonk_service;
pub mod secp256k1_service;
pub mod service_runner;
pub mod sha3_service;
pub mod shell_service;
pub mod softirq_service;
pub mod storage_service;
pub mod tls_service;
pub mod udev_service;
pub mod vfs_service;
pub mod wallet_service;
pub mod zk_service;
pub mod zkprover_service;

pub use aes_service::run_aes_service;
pub use agents_service::run_agents_service;
pub use apps_service::run_apps_service;
pub use audio_service::run_audio_service;
pub use blake3_service::run_blake3_service;
pub use chacha_service::run_chacha_service;
pub use crypto_service::run_crypto_service;
pub use dilithium_service::run_dilithium_service;
pub use display_service::run_display_service;
pub use drivers::run_driver_manager;
pub use ed25519_service::run_ed25519_service;
pub use entropy_service::run_entropy_service;
pub use gpu_service::run_gpu_service;
pub use groth16_service::run_groth16_service;
pub use init::run_init;
pub use input_service::run_input_service;
pub use keyring_service::run_keyring_service;
pub use kworker_service::run_kworker_service;
pub use kyber_service::run_kyber_service;
pub use net_service::run_net_service;
pub use netmgr_service::run_netmgr_service;
pub use plonk_service::run_plonk_service;
pub use secp256k1_service::run_secp256k1_service;
pub use service_runner::run_service_by_name;
pub use sha3_service::run_sha3_service;
pub use shell_service::run_shell_service;
pub use softirq_service::run_softirq_service;
pub use storage_service::run_storage_service;
pub use tls_service::run_tls_service;
pub use udev_service::run_udev_service;
pub use vfs_service::run_vfs_service;
pub use wallet_service::run_wallet_service;
pub use zk_service::run_zk_service;
pub use zkprover_service::run_zkprover_service;

#[cfg(test)]
pub mod tests;
