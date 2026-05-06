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

//! Wire-form constants the kernel-side client and the userland
//! capsule both speak. Drift between the two manifests as
//! `DriverRngError::ProtocolMismatch`; the userland mirror lives
//! at `userland/capsule_driver_virtio_rng/src/protocol/header.rs`.

pub(in super::super) const MAGIC: u32 = 0x4E4F_5244; // "NORD"
pub(in super::super) const VERSION: u16 = 1;

pub(in super::super) const MAX_FILL_BYTES: u32 = 4096;
pub(in super::super) const MAX_PAYLOAD_BYTES: u32 = 4096;
