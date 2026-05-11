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

use super::embed::DESKTOP_SHELL_ELF;
use crate::capabilities::Capability;
use crate::kernel_core::process_spawn::capsule_spawn::{self, CapsuleSpec, SpawnError};

const SERVICE_NAME: &str = "desktop_shell";
const SERVICE_PORT: u32 = 4410;
const REPLY_INBOX: &str = "endpoint.desktop_shell.reply";
const REPLY_PORT: u32 = 4411;

pub fn spawn_desktop_shell_capsule() -> Result<(), SpawnError> {
    if DESKTOP_SHELL_ELF.is_empty() {
        return Err(SpawnError::FeatureDisabled);
    }
    let mut caps_bits = 0u64;
    for cap in [
        Capability::CoreExec,
        Capability::Memory,
        Capability::Debug,
        Capability::IPC,
    ] {
        caps_bits |= cap.bit();
    }
    let spec = CapsuleSpec {
        name: SERVICE_NAME,
        service_port: SERVICE_PORT,
        reply_inbox: REPLY_INBOX,
        reply_port: REPLY_PORT,
        elf: DESKTOP_SHELL_ELF,
        caps_bits,
        debug_tag: b"[DESKTOP-SHELL-DEBUG] load_elf_executable error:",
    };
    let _ = capsule_spawn::spawn(&spec)?;
    Ok(())
}
