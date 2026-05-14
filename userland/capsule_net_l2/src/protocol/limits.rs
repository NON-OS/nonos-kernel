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

//! Wire-side limits. The ethernet MTU is the standard 1500 plus
//! the 14-byte header; the IPC payload allows a small margin on
//! top so a caller can wrap a v1 envelope around a full-MTU
//! frame without splitting.

pub const ETH_HDR_LEN: usize = 14;
pub const ETH_PAYLOAD_MAX: usize = 1500;
pub const ETH_FRAME_MAX: usize = ETH_HDR_LEN + ETH_PAYLOAD_MAX;
pub const IPC_PAYLOAD_MAX: usize = ETH_FRAME_MAX + 64;
pub const ARP_SNAPSHOT_MAX_ENTRIES: u32 = 64;
