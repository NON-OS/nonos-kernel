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

use super::client::REPLY_INBOX;
use super::embed::KEYRING_ELF;
use super::state;
use crate::capabilities::Capability;
use crate::kernel_core::process_spawn::capsule_spawn::{self, CapsuleSpec};

pub use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;

const SERVICE_NAME: &str = "keyring";
const SERVICE_PORT: u32 = 4098;
const REPLY_PORT: u32 = 4099;

// The capsule itself never needs CAP_KEYRING — it is the keyring.
// Bits below are what the userland binary needs to run: IPC for
// MkIpc recv/send, Memory for heap_init/mmap, Crypto for any
// kernel crypto syscall the implementation may reach.
pub fn spawn_keyring_capsule() -> Result<(), SpawnError> {
    let spec = CapsuleSpec {
        name: SERVICE_NAME,
        service_port: SERVICE_PORT,
        reply_inbox: REPLY_INBOX,
        reply_port: REPLY_PORT,
        elf: KEYRING_ELF,
        caps_bits: Capability::IPC.bit() | Capability::Memory.bit() | Capability::Crypto.bit(),
        debug_tag: b"[KEYRING-DEBUG] load_elf_executable error:",
    };
    let pid = capsule_spawn::spawn(&spec)?;
    state::set_alive(pid);
    Ok(())
}
