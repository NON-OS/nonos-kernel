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

//! Owning handle for one broker DMA grant. `device_addr` is the
//! address the controller hands to its bus master; `user_va` is
//! the address the capsule's CPU dereferences. The underlying
//! grant is released by the `Drop` impl in a sibling file.

#[derive(Debug)]
pub struct DmaRegion {
    pub(super) user_va: u64,
    pub(super) device_addr: u64,
    pub(super) length: u64,
    pub(super) grant_id: u64,
}
