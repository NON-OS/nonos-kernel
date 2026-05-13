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

use core::mem::size_of;

// Userland sees both records as 16-byte fixed-shape blobs. Field
// order is ABI; do not reorder.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct IrqBindOut {
    pub(super) grant_id: u64,
    pub(super) vector: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct IrqPollOut {
    pub(super) seq: u64,
    pub(super) overflow: u64,
}

const _: () = assert!(size_of::<IrqBindOut>() == 16);
const _: () = assert!(size_of::<IrqPollOut>() == 16);
