// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::types::{ProcessState, Priority};
use super::table::create_process_with_mem;

pub(crate) fn init_system_processes() {
    init_kernel_processes();
    init_crypto_processes();
    init_system_services();
    crate::log::info!("[PROCESS] System processes initialized");
}

fn init_kernel_processes() {
    let _ = create_process_with_mem("kernel", ProcessState::Running, Priority::RealTime, 8192);
    let _ = create_process_with_mem("init", ProcessState::Running, Priority::High, 256);
    let _ = create_process_with_mem("kworker/0", ProcessState::Sleeping, Priority::Normal, 128);
    let _ = create_process_with_mem("ksoftirqd", ProcessState::Sleeping, Priority::Normal, 64);
    let _ = create_process_with_mem("desktop", ProcessState::Running, Priority::High, 4096);
    let _ = create_process_with_mem("compositor", ProcessState::Running, Priority::High, 2048);
}

fn init_crypto_processes() {
    let _ = create_process_with_mem("crypto-core", ProcessState::Running, Priority::RealTime, 1024);
    let _ = create_process_with_mem("entropy-pool", ProcessState::Running, Priority::High, 512);
    let _ = create_process_with_mem("keyring-srv", ProcessState::Running, Priority::High, 2048);
    let _ = create_process_with_mem("aes-engine", ProcessState::Running, Priority::High, 256);
    let _ = create_process_with_mem("chacha-eng", ProcessState::Running, Priority::High, 256);
    let _ = create_process_with_mem("sha3-hasher", ProcessState::Running, Priority::High, 128);
    let _ = create_process_with_mem("blake3-srv", ProcessState::Running, Priority::High, 128);
    let _ = create_process_with_mem("ed25519-srv", ProcessState::Sleeping, Priority::Normal, 512);
    let _ = create_process_with_mem("secp256k1", ProcessState::Sleeping, Priority::Normal, 1024);
    let _ = create_process_with_mem("zk-prover", ProcessState::Sleeping, Priority::Normal, 16384);
    let _ = create_process_with_mem("groth16-v", ProcessState::Sleeping, Priority::Normal, 8192);
    let _ = create_process_with_mem("plonk-srv", ProcessState::Sleeping, Priority::Normal, 4096);
    let _ = create_process_with_mem("kyber-pqc", ProcessState::Sleeping, Priority::Normal, 768);
    let _ = create_process_with_mem("dilithium", ProcessState::Sleeping, Priority::Normal, 512);
}

fn init_system_services() {
    let _ = create_process_with_mem("network-mgr", ProcessState::Sleeping, Priority::Normal, 384);
    let _ = create_process_with_mem("tls-daemon", ProcessState::Sleeping, Priority::Normal, 1024);
    let _ = create_process_with_mem("wallet-srv", ProcessState::Running, Priority::High, 2048);
    let _ = create_process_with_mem("storage-mgr", ProcessState::Sleeping, Priority::Normal, 256);
    let _ = create_process_with_mem("udevd", ProcessState::Sleeping, Priority::Normal, 192);
}
