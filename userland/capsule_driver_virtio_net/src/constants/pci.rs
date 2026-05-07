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

//! PCI identifiers for virtio-net. Both transitional (legacy
//! 0x1000) and modern (0x1041) device IDs are accepted; the
//! capsule still drives the legacy BAR0 register window either
//! way.

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;
pub const VIRTIO_NET_MODERN: u16 = 0x1041;

pub const BAR_INDEX: u32 = 0;
pub const BAR_OFFSET: u64 = 0;
