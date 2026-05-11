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

//! e1000 RX / TX descriptor layout and ring sizing. The legacy
//! descriptors are 16 bytes each; ring base addresses go into
//! RDBAL/H and TDBAL/H, ring length in bytes into RDLEN/TDLEN.
//! The 8254x manual requires 128-byte ring alignment, which the
//! broker DMA grant satisfies trivially because every grant is
//! page-aligned (4 KiB ⊆ 128 B).
//!
//! `RX_DESC_COUNT` and `TX_DESC_COUNT` are kept small to fit each
//! ring inside one 4 KiB DMA grant. Each direction takes one
//! grant for the ring and a second for the buffer pool.

pub const DESC_BYTES: usize = 16;

pub const RX_DESC_COUNT: usize = 32;
pub const TX_DESC_COUNT: usize = 32;

pub const RX_RING_BYTES: usize = RX_DESC_COUNT * DESC_BYTES;
pub const TX_RING_BYTES: usize = TX_DESC_COUNT * DESC_BYTES;

pub const RX_BUFFER_LEN: usize = 2048;
pub const TX_BUFFER_LEN: usize = 2048;

pub const RX_BUFFER_POOL_BYTES: usize = RX_DESC_COUNT * RX_BUFFER_LEN;
pub const TX_BUFFER_POOL_BYTES: usize = TX_DESC_COUNT * TX_BUFFER_LEN;

// Legacy RX descriptor status bit. `DD` flips when the device
// has written a frame; the consumer reads it before reading
// `length`. The capsule does not yet support multi-fragment RX,
// so `EOP` is implicit per descriptor and not checked.
pub const RX_STATUS_DD: u8 = 1 << 0;

// Legacy TX descriptor command + status bits.
pub const TX_CMD_EOP: u8 = 1 << 0;
pub const TX_CMD_IFCS: u8 = 1 << 1;
pub const TX_CMD_RS: u8 = 1 << 3;
pub const TX_STATUS_DD: u8 = 1 << 0;
