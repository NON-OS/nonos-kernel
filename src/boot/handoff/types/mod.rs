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

pub mod constants;
pub mod framebuffer;
pub mod memory;
pub mod info;
pub mod security;
pub mod handoff;
#[cfg(test)]
mod tests;

pub use constants::{HANDOFF_MAGIC, HANDOFF_VERSION, flags, pixel_format};
pub use constants::{validate_cmdline_len, truncate_cmdline};
pub use framebuffer::FramebufferInfo;
pub use memory::{memory_type, MemoryMapEntry, MemoryMap};
pub use info::{AcpiInfo, SmbiosInfo, Module, Modules, Timing};
pub use security::{Measurements, ZkAttestation, RngSeed};
pub use handoff::BootHandoffV1;

pub const MAX_CMDLINE: usize = constants::MAX_CMDLINE_LEN;
