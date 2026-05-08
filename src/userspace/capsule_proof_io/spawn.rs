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

//! Spawn proof_io as a regular capsule. Used by the user-entry proof
//! profile so proof_io is the first CPL=3 binary on the run queue;
//! its `_start` is two syscalls (MkDebug, MkExit), so a successful
//! boot proves SYSCALL/SYSRET end-to-end before any heavier capsule
//! comes up.

use super::embed::PROOF_IO_ELF;
use crate::capabilities::Capability;
use crate::kernel_core::process_spawn::capsule_spawn::{self, CapsuleSpec};

pub use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;

const SERVICE_NAME: &str = "proof_io";
const SERVICE_PORT: u32 = 4100;
const REPLY_INBOX: &str = "endpoint.proof_io.reply";
const REPLY_PORT: u32 = 4101;

pub fn spawn_proof_io_capsule() -> Result<(), SpawnError> {
    let spec = CapsuleSpec {
        name: SERVICE_NAME,
        service_port: SERVICE_PORT,
        reply_inbox: REPLY_INBOX,
        reply_port: REPLY_PORT,
        elf: PROOF_IO_ELF,
        caps_bits: Capability::IPC.bit() | Capability::Memory.bit(),
        debug_tag: b"[PROOF-IO-DEBUG] load_elf_executable error:",
    };
    capsule_spawn::spawn(&spec)?;
    Ok(())
}
