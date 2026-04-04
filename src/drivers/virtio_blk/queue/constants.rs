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

pub(super) const QUEUE_SIZE: u16 = 128;
pub(super) const DATA_BUF_SIZE: usize = 128 * 1024;
pub(super) const VQ_REGION_SIZE: usize = 16384;

pub(super) const DESC_OFFSET: usize = 0;
pub(super) const AVAIL_OFFSET: usize = 2048;
pub(super) const USED_OFFSET: usize = 4096;

pub(super) const VIRTQ_DESC_F_NEXT: u16 = 1;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = 2;
