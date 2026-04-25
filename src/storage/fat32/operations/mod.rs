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

pub mod cluster;
pub mod create;
pub mod dir;
pub mod file;
pub mod read;
pub mod write;

pub use cluster::{
    allocate_cluster_chain, extend_cluster_chain, find_free_cluster, free_cluster_chain,
    is_bad_cluster, is_eof, is_free_cluster, read_fat_entry, truncate_cluster_chain,
    write_fat_entry,
};
pub use create::{create_file, update_file};
pub use dir::{find_free_dir_slot, make_dir_entry, update_dir_entry};
pub use file::{delete_file, rename_file};
pub use read::{count_directory_entries, find_file, read_directory, read_file};
pub use write::write_cluster;
