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

//! Per-op payload sizes the server enforces. A frame larger than
//! `MAX_ETHERNET_FRAME` is refused at the IPC boundary so a
//! misbehaving caller cannot drive the TX DMA buffer past its
//! grant.

use crate::constants::{MAC_LEN, MAX_ETHERNET_FRAME};

pub const STATUS_LEN: usize = 4;

pub const MAX_TX_PAYLOAD_BYTES: u32 = MAX_ETHERNET_FRAME as u32;
pub const MAC_ADDRESS_PAYLOAD_LEN: usize = MAC_LEN;
pub const LINK_STATUS_PAYLOAD_LEN: usize = 1;
pub const STATS_PAYLOAD_LEN: usize = 48;
// rx_packet body: u32 length followed by frame bytes.
pub const RX_PAYLOAD_PREFIX_LEN: usize = 4;
