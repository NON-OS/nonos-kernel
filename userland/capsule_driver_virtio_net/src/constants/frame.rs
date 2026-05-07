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

//! Ethernet and virtio-net frame sizing. The capsule never reads
//! anything inside a frame — that is the job of whoever consumes
//! the bytes — but it does enforce the spec's lower and upper
//! bounds at the IPC boundary so a misbehaving caller cannot
//! drive a DMA buffer past its grant.

const ETH_HEADER_LEN: usize = 14;
pub const MIN_ETHERNET_FRAME: usize = 60;
const MTU: usize = 1500;
pub const MAX_ETHERNET_FRAME: usize = MTU + ETH_HEADER_LEN;

// Virtio-net spec §5.1.6: legacy / no-mergeable-rxbuf header is 10
// bytes; modern with mrg-rxbuf is 12. We always negotiate features
// without `VIRTIO_NET_F_MRG_RXBUF`, so 12-byte form is what the
// device uses today, but reserving the larger value is safe.
pub const VIRTIO_NET_HDR_LEN: usize = 12;

pub const MAC_LEN: usize = 6;
