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

pub(crate) const DRIVER_SERVICES: &[&str] = &["drivers"];

pub(crate) const KERNEL_SERVICES: &[&str] = &["kworker", "softirq"];

pub(crate) const CRYPTO_ENGINE_SERVICES: &[&str] =
    &["entropy", "keyring", "aes", "chacha", "sha3", "blake3"];

pub(crate) const SIGNATURE_SERVICES: &[&str] = &["ed25519", "secp256k1"];

pub(crate) const ZK_SERVICES: &[&str] = &["zkprover", "groth16", "plonk"];

pub(crate) const PQ_CRYPTO_SERVICES: &[&str] = &["kyber", "dilithium"];

pub(crate) const SYSTEM_SERVICES: &[&str] = &["netmgr", "tls", "wallet", "storage", "udev"];

pub(crate) const CORE_SERVICES: &[&str] = &[
    "vfs", "display", "input", "network", "crypto", "zk", "audio", "gpu", "apps", "agents",
    "shell", "desktop",
];
