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

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_NET_DEVICE_ID: u16 = 0x1000;
pub const VIRTIO_NET_MODERN_ID: u16 = 0x1041;

pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
pub const VIRTIO_NET_F_CSUM: u32 = 1 << 0;

pub const REG_DEVICE_FEATURES: u32 = 0x00;
pub const REG_DRIVER_FEATURES: u32 = 0x04;
pub const REG_QUEUE_ADDRESS: u32 = 0x08;
pub const REG_QUEUE_SIZE: u32 = 0x0C;
pub const REG_QUEUE_SELECT: u32 = 0x0E;
pub const REG_QUEUE_NOTIFY: u32 = 0x10;
pub const REG_DEVICE_STATUS: u32 = 0x12;
pub const REG_ISR_STATUS: u32 = 0x13;
pub const REG_MAC_BASE: u32 = 0x14;

pub const VIRTQ_RX: u16 = 0;
pub const VIRTQ_TX: u16 = 1;

pub const QUEUE_SIZE: usize = 32;
pub const BUFFER_SIZE: usize = 2048;

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
