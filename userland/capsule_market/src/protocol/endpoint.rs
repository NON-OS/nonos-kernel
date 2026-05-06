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

//! Reply inbox the kernel client owns. Slot 7 in the per-service
//! numbering (ramfs=1, keyring=2, entropy=3, crypto=4, vfs=5,
//! virtio_rng=6, market=7).

pub(in super::super) const KERNEL_REPLY_ENDPOINT: u64 = 0x1_0000_0007;
