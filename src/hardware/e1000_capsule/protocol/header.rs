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

//! Wire-form constants shared with the userland mirror at
//! `userland/capsule_driver_e1000/src/protocol/header.rs` and
//! `.../src/protocol/limits.rs`. Drift surfaces as
//! `DriverNetError::ProtocolMismatch`. The MTU + frame bounds
//! match `virtio_net_capsule` so a single net-stack client can
//! drive either backend.

pub(in super::super) const MAGIC: u32 = 0x4E45_3130; // "NE10"
pub(in super::super) const VERSION: u16 = 1;

pub(in super::super) const MAC_LEN: usize = 6;
pub(in super::super) const ETH_HEADER_LEN: usize = 14;
pub(in super::super) const MTU: usize = 1500;
pub(in super::super) const MIN_ETHERNET_FRAME: usize = 60;
pub(in super::super) const MAX_ETHERNET_FRAME: usize = MTU + ETH_HEADER_LEN;
pub(in super::super) const MAX_TX_PAYLOAD_BYTES: u32 = MAX_ETHERNET_FRAME as u32;

// Response cap. Largest reply is rx_packet (status + 4-byte
// length prefix + frame).
pub(in super::super) const MAX_PAYLOAD_BYTES: u32 = MAX_ETHERNET_FRAME as u32 + 32;
