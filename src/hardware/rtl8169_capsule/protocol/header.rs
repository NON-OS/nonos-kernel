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

pub(in super::super) const MAGIC: u32 = 0x4E52_3639;
pub(in super::super) const VERSION: u16 = 1;

pub(in super::super) const MAC_LEN: usize = 6;
pub(in super::super) const ETH_HEADER_LEN: usize = 14;
pub(in super::super) const MTU: usize = 1500;
pub(in super::super) const MIN_ETHERNET_FRAME: usize = 60;
pub(in super::super) const MAX_ETHERNET_FRAME: usize = MTU + ETH_HEADER_LEN;
pub(in super::super) const MAX_TX_PAYLOAD_BYTES: u32 = MAX_ETHERNET_FRAME as u32;
pub(in super::super) const MAX_PAYLOAD_BYTES: u32 = MAX_ETHERNET_FRAME as u32 + 32;
pub(in super::super) const STATS_PAYLOAD_LEN: usize = 48;
