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

//! Virtqueue layout, descriptor flags, and per-queue bounds. The
//! capsule programs two virtqueues — RX = 0, TX = 1 — both at the
//! legacy 8 KiB region size with the used ring on the second
//! page. Each region is its own DMA grant; data buffers live in
//! separate pools.
//!
//! RX is pre-filled with `RX_DESC_COUNT` device-write descriptors
//! before DRIVER_OK is set; TX uses a single descriptor that is
//! reused per outbound packet (one outstanding at a time).

pub const Q_RX: u16 = 0;
pub const Q_TX: u16 = 1;

pub const QUEUE_SIZE: u16 = 8;
pub const VRING_DESC_F_WRITE: u16 = 2;

pub const VQ_DESC_OFFSET: usize = 0;
pub const VQ_AVAIL_OFFSET: usize = 256;
pub const VQ_USED_OFFSET: usize = 4096;
pub const VQ_REGION_SIZE: usize = 8192;

// One slot per RX descriptor. With QUEUE_SIZE = 8 the device can
// post up to 8 received frames before the capsule must walk the
// used ring; that holds for the bounded smoke workload.
pub const RX_DESC_COUNT: u16 = QUEUE_SIZE;

// Buffer sizes include the 12-byte virtio-net header that prefixes
// every frame on both directions. 2 KiB matches the legacy buffer
// size and is large enough for a 1500-byte MTU plus the header.
pub const RX_BUFFER_LEN: u32 = 2048;
pub const TX_BUFFER_LEN: u32 = 2048;
