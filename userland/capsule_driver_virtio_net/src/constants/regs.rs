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

//! Legacy virtio-pci register offsets in BAR0. The shared block
//! (host_features..isr) follows the virtio 1.x spec §4.1.4.8;
//! `LEG_MAC` is the start of the per-device-class config window
//! which for virtio-net carries the 6-byte MAC followed by a
//! 2-byte status word when `VIRTIO_NET_F_STATUS` is negotiated.

pub const LEG_HOST_FEATURES: usize = 0x00;
pub const LEG_GUEST_FEATURES: usize = 0x04;
pub const LEG_QUEUE_PFN: usize = 0x08;
pub const LEG_QUEUE_NUM: usize = 0x0C;
pub const LEG_QUEUE_SEL: usize = 0x0E;
pub const LEG_QUEUE_NOTIFY: usize = 0x10;
pub const LEG_STATUS: usize = 0x12;
pub const LEG_MAC: usize = 0x14;

// Net-config status word lives 6 bytes after LEG_MAC. Only valid
// when VIRTIO_NET_F_STATUS was negotiated; without that feature
// the capsule treats the link as unconditionally up.
pub const LEG_NET_STATUS_OFFSET: usize = LEG_MAC + 6;

// Feature bits this capsule recognises.
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_STATUS: u32 = 16;

// Net-config status bits.
pub const VIRTIO_NET_S_LINK_UP: u16 = 1;
