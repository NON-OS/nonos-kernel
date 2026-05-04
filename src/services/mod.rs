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

// Service primitives — the registry, the per-service capability table,
// the typed message protocol, the client/server scaffolding. These
// are kernel-resident plumbing; capsules talk through them.

pub mod caps;
pub mod client;
pub mod lifecycle;
pub mod protocol;
pub mod registry;
pub mod server;

pub use caps::{check_service_cap, has_capability, verify_caller_cap, CapError, ServiceCap};
pub use caps::{
    CAP_ADMIN, CAP_AGENTS, CAP_APPS, CAP_AUDIO, CAP_CRYPTO, CAP_DISPLAY, CAP_DRIVER, CAP_GPU,
    CAP_INPUT, CAP_NET, CAP_SHELL, CAP_VFS, CAP_ZK,
};
pub use client::ServiceClient;
pub use protocol::{ServiceMessage, ServiceRequest, ServiceResponse};
pub use registry::{lookup_service, register_endpoint, ServiceEndpoint};
pub use server::ServiceServer;

// Kernel-resident `*_engine` wrappers. Not real userland; they are
// kernel threads in PCB clothing that respond on the service registry.
// Migration to real userland capsules under `userland/capsule_<name>/`
// is the M-phase work. Off in every microkernel profile.
#[cfg(feature = "nonos-legacy-tree")]
pub mod aes_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod agents_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod apps_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod audio_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod blake3_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod chacha_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod crypto_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod desktop_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod dilithium_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod display_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod driver_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod ed25519_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod entropy_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod gpu_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod groth16_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod input_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod kworker_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod kyber_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod net_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod netmgr_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod plonk_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod secp256k1_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod sha3_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod shell_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod softirq_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod storage_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod tls_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod udev_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod vfs_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod wallet_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod wallpaper_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zk_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zkprover_engine;

#[cfg(test)]
pub mod tests;
