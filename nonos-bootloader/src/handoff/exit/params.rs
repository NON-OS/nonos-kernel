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

use crate::firmware::FirmwareHandoff;
use crate::handoff::types::{CryptoHandoff, FramebufferInfo};

pub struct HandoffInitParams {
    pub fb_info: FramebufferInfo,
    pub acpi_rsdp: u64,
    pub smbios_entry: u64,
    pub unix_epoch_ms: u64,
    pub tsc_hz: u64,
    pub handoff_flags: u64,
    pub entry_point: u64,
    pub cmdline_addr: u64,
    pub crypto: CryptoHandoff,
    pub firmware: FirmwareHandoff,
    pub rng_seed: [u8; 32],
}
