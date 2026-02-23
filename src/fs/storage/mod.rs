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

mod error;
mod types;
mod stats;
mod quota;

pub use error::{StorageError, StorageResult};
pub use types::*;
pub use stats::*;
pub use quota::*;

pub fn get_storage_stats() -> StorageStats {
    stats::calculate_storage_stats()
}

pub fn get_total_used_bytes() -> usize {
    stats::get_total_storage_used()
}

pub fn get_total_available_bytes() -> usize {
    stats::get_total_storage_available()
}

pub fn get_storage_usage_percent() -> f32 {
    stats::get_usage_percentage()
}

pub fn get_filesystem_breakdown() -> FilesystemBreakdown {
    stats::get_breakdown_by_filesystem()
}

pub fn get_storage_health() -> StorageHealth {
    stats::check_storage_health()
}

pub fn get_inode_stats() -> InodeStats {
    stats::get_inode_statistics()
}
