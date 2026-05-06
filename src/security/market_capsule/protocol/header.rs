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

//! Wire-form constants the kernel client and the userland capsule
//! both speak. Drift between the two manifests as
//! `MarketError::ProtocolMismatch`. The userland mirror lives at
//! `userland/capsule_market/src/protocol/header.rs`.

pub(in super::super) const MAGIC: u32 = 0x4E4D_4B54; // "NMKT"
pub(in super::super) const VERSION: u16 = 1;

// Response cap. The largest reply today is `OP_LOAD_INDEX`'s
// status reply (4 bytes), but the response transport must hold
// a `OP_GET_APP` / `OP_GET_RELEASE` reply that carries listing
// metadata. 64 KiB matches the userland TX buffer.
pub(in super::super) const MAX_PAYLOAD_BYTES: u32 = 64 * 1024;
