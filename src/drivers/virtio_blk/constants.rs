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

pub const VIRTIO_BLK_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_BLK_DEVICE_ID_TRANSITIONAL: u16 = 0x1001;
pub const VIRTIO_BLK_DEVICE_ID_MODERN: u16 = 0x1042;

pub(super) const VIRTIO_BLK_T_IN: u32 = 0;
pub(super) const VIRTIO_BLK_T_OUT: u32 = 1;
pub(super) const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub(super) const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub(super) const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub(super) const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

pub(super) const VIRTIO_BLK_S_OK: u8 = 0;
pub(super) const VIRTIO_BLK_S_IOERR: u8 = 1;
pub(super) const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub(super) const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
pub(super) const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
pub(super) const VIRTIO_BLK_F_GEOMETRY: u32 = 4;
pub(super) const VIRTIO_BLK_F_RO: u32 = 5;
pub(super) const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
pub(super) const VIRTIO_BLK_F_FLUSH: u32 = 9;
pub(super) const VIRTIO_BLK_F_DISCARD: u32 = 13;

pub(super) const LEG_HOST_FEATURES: u16 = 0x00;
pub(super) const LEG_GUEST_FEATURES: u16 = 0x04;
pub(super) const LEG_QUEUE_PFN: u16 = 0x08;
pub(super) const LEG_QUEUE_NUM: u16 = 0x0C;
pub(super) const LEG_QUEUE_SEL: u16 = 0x0E;
pub(super) const LEG_NOTIFY: u16 = 0x10;
pub(super) const LEG_STATUS: u16 = 0x12;
pub(super) const LEG_CFG_CAPACITY: u16 = 0x14;

pub(super) const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub(super) const VIRTIO_STATUS_DRIVER: u8 = 2;
pub(super) const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub(super) const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

pub const SECTOR_SIZE: usize = 512;
pub(super) const MAX_SECTORS_PER_REQUEST: usize = 256;
pub(super) const DEFAULT_TIMEOUT_MS: u64 = 5000;
