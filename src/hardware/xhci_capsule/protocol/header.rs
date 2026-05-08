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

//! Wire-form constants the kernel client and the userland xHCI
//! capsule both speak. Drift between the two manifests as
//! `DriverXhciError::ProtocolMismatch`. The userland mirror is at
//! `userland/capsule_driver_xhci/src/protocol/header.rs` and
//! `protocol/limits.rs`.

pub(in super::super) const MAGIC: u32 = 0x4E58_4843; // "NXHC"
pub(in super::super) const VERSION: u16 = 1;

/// PORT_STATUS reply caps out at this many port entries; the
/// userland capsule clamps `max_ports` to the same bound. Reply
/// payload size: 4 (port_count + pad) + N * 8.
pub(in super::super) const MAX_PORTS_REPORTED: usize = 255;
pub(in super::super) const PORT_ENTRY_BYTES: usize = 8;
pub(in super::super) const PORT_STATUS_HEADER_BYTES: usize = 4;
pub(in super::super) const CONTROLLER_STATUS_PAYLOAD_LEN: usize = 52;

pub(in super::super) const MAX_PAYLOAD_BYTES: u32 =
    (PORT_STATUS_HEADER_BYTES + MAX_PORTS_REPORTED * PORT_ENTRY_BYTES + 64) as u32;
