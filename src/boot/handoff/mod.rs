// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod api;
mod types;
#[cfg(test)]
mod tests;

pub use api::{get_handoff, init_handoff, is_initialized, total_memory, HandoffError};
pub use types::{flags, memory_type, pixel_format};
pub use types::{HANDOFF_MAGIC, HANDOFF_VERSION};
pub use types::{
    AcpiInfo, BootHandoffV1, FramebufferInfo, Measurements, MemoryMap, MemoryMapEntry, Module,
    Modules, RngSeed, SmbiosInfo, Timing,
};
