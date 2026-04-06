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

mod types;
mod helpers;
mod lookup;
mod add;
mod remove;
mod iterate;

pub use types::Ext4DirEntry;
pub use types::{EXT4_FT_UNKNOWN, EXT4_FT_REG_FILE, EXT4_FT_DIR, EXT4_FT_CHRDEV};
pub use types::{EXT4_FT_BLKDEV, EXT4_FT_FIFO, EXT4_FT_SOCK, EXT4_FT_SYMLINK};
pub use lookup::dir_lookup;
pub use add::dir_add_entry;
pub use remove::dir_remove_entry;
pub use iterate::dir_iterate;
