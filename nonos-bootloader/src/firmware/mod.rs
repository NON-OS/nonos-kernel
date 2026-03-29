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

// Embedded WiFi firmware handoff for kernel boot

mod loader;
pub mod quirks;
mod types;

pub use loader::{firmware_count, get_firmware, get_firmware_handoff, has_embedded_firmware};
pub use quirks::{apply_mmap_quirks, detect_firmware_quirks, FirmwareQuirk, QuirkFlags};
pub use types::{FirmwareEntry, FirmwareHandoff, FirmwareType, MAX_FIRMWARE_ENTRIES};
