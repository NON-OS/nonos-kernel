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

//! Spawn the xHCI driver capsule with the broker capability
//! bundle. P0 needs IPC + Memory + Driver + Mmio + Irq + Dma. No
//! Pio (xHCI is MMIO-only). MSI/MSI-X are not in the broker; INTx
//! is documented as the P0 interrupt path.

use super::client::REPLY_INBOX;
use super::embed::DRIVER_XHCI_ELF;
use super::state;
use crate::capabilities::Capability;
use crate::kernel_core::process_spawn::capsule_spawn::{self, CapsuleSpec};

pub use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;

const SERVICE_NAME: &str = "driver.xhci0";
const SERVICE_PORT: u32 = 4206;
const REPLY_PORT: u32 = 4207;

pub fn spawn_driver_xhci_capsule() -> Result<(), SpawnError> {
    let spec = CapsuleSpec {
        name: SERVICE_NAME,
        service_port: SERVICE_PORT,
        reply_inbox: REPLY_INBOX,
        reply_port: REPLY_PORT,
        elf: DRIVER_XHCI_ELF,
        caps_bits: Capability::IPC.bit()
            | Capability::Memory.bit()
            | Capability::Driver.bit()
            | Capability::Mmio.bit()
            | Capability::Irq.bit()
            | Capability::Dma.bit(),
        debug_tag: b"[DRIVER-XHCI] load_elf_executable error:",
    };
    let pid = capsule_spawn::spawn(&spec)?;
    state::set_alive(pid);
    Ok(())
}
