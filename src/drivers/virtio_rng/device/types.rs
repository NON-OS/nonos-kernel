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

pub(super) const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub(super) const VIRTIO_STATUS_DRIVER: u8 = 2;
pub(super) const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub(super) const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

pub(super) const LEG_HOST_FEATURES: u16 = 0x00;
pub(super) const LEG_GUEST_FEATURES: u16 = 0x04;
pub(super) const LEG_QUEUE_PFN: u16 = 0x08;
pub(super) const LEG_QUEUE_NUM: u16 = 0x0C;
pub(super) const LEG_QUEUE_SEL: u16 = 0x0E;
pub(super) const LEG_NOTIFY: u16 = 0x10;
pub(super) const LEG_STATUS: u16 = 0x12;

pub enum AccessMode {
    Io(u16),
    Mmio(u64),
}
