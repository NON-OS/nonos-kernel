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

//! Ethernet sizing. The capsule never inspects frame contents but
//! enforces the upper bound at the IPC boundary so a misbehaving
//! caller cannot drive the TX DMA buffer past its grant. The
//! formula matches `capsule_driver_virtio_net::constants::frame`
//! so the shared kernel-side network client sees one envelope
//! across both NIC backends. `RCTL.SECRC = 1` strips FCS in
//! hardware, so RX descriptors deliver at most `MAX_ETHERNET_FRAME`
//! bytes (no FCS) into the buffer.

const ETH_HEADER_LEN: usize = 14;
const MTU: usize = 1500;

pub const MAC_LEN: usize = 6;
pub const MIN_ETHERNET_FRAME: usize = 60;
pub const MAX_ETHERNET_FRAME: usize = MTU + ETH_HEADER_LEN;
