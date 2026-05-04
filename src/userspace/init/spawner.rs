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

use crate::kernel_core::spawn_isolated_service;
use crate::services::caps::*;
use crate::sys::boot_log;

pub(super) fn spawn_services(services: &[&str]) {
    for &name in services {
        boot_log::stage("SPAWN", name);
        spawn_svc(name, cap_for_service(name));
    }
}

pub(super) fn spawn_driver_services(services: &[&str]) {
    for &name in services {
        spawn_svc(name, CAP_DRIVER);
    }
}

pub(super) fn spawn_core_services(services: &[&str]) {
    spawn_services(services);
}

pub(crate) fn cap_for_service(name: &str) -> u64 {
    match name {
        "vfs" => CAP_VFS,
        "network" => CAP_NET,
        "display" => CAP_DISPLAY,
        "input" => CAP_INPUT,
        "crypto" => CAP_CRYPTO,
        "zk" => CAP_ZK,
        "audio" => CAP_AUDIO,
        "gpu" => CAP_GPU,
        "apps" => CAP_APPS,
        "agents" => CAP_AGENTS,
        "shell" => CAP_SHELL,
        "desktop" => CAP_DISPLAY | CAP_INPUT,
        "kworker" | "softirq" => CAP_KERNEL | CAP_MEMORY | CAP_PROCESS,
        "entropy" => CAP_ENTROPY | CAP_CRYPTO,
        "aes" | "chacha" | "sha3" | "blake3" => CAP_CRYPTO,
        "ed25519" | "secp256k1" => CAP_CRYPTO,
        "zkprover" | "groth16" | "plonk" => CAP_ZK | CAP_CRYPTO,
        "kyber" | "dilithium" => CAP_CRYPTO,
        "netmgr" => CAP_NET,
        "tls" => CAP_TLS | CAP_CRYPTO | CAP_NET,
        "wallet" => CAP_WALLET | CAP_CRYPTO,
        "storage" => CAP_STORAGE | CAP_VFS,
        "udev" => CAP_UDEV | CAP_DRIVER,
        _ => 0,
    }
}

fn spawn_svc(name: &str, caps: u64) {
    match spawn_isolated_service(name, caps) {
        Ok(_) => boot_log::ok("INIT", name),
        Err(_) => boot_log::error(name),
    }
}
