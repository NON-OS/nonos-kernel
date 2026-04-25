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

mod capacity;
mod control;
mod inquiry_cmd;
mod read;
mod unit;
mod write;

pub use capacity::{get_capacity, read_capacity_10, read_capacity_16};
pub use control::{eject_media, is_write_protected, lock_media, sync_cache};
pub use inquiry_cmd::inquiry;
pub use read::{read_blocks, read_blocks_16, read_blocks_auto};
pub use unit::{request_sense, test_unit_ready};
pub use write::{write_blocks, write_blocks_16, write_blocks_auto};
