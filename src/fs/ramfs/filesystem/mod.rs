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

pub mod atomic;
pub mod core;
pub mod crypto;
pub mod global;
pub mod global_dir;
pub mod key;
pub mod legacy;
pub mod list;
pub mod ops;
pub mod ops_write;
pub mod path;

pub use core::NonosFilesystem;
pub use global::{
    create_file, delete, delete_file, exists, file_exists, get_filesystem, init_nonos_filesystem,
    init_nonos_fs, list_files, read_file, rename, stats, write_file, write_or_create,
    NONOS_FILESYSTEM,
};
pub use global_dir::{create_dir, dir_exists, list_dir, list_dir_entries, mkdir_all};
pub use legacy::{
    create_file_legacy, delete_file_legacy, list_dir_legacy, read_file_legacy, write_file_legacy,
};
pub use path::normalize_path;

#[cfg(test)]
mod tests {
    use super::super::error::FsError;
    use super::super::types::secure_zeroize;
    use super::path::validate_path;

    #[test]
    fn test_fs_error_to_errno() {
        assert_eq!(FsError::NotFound.to_errno(), -2);
        assert_eq!(FsError::AlreadyExists.to_errno(), -17);
        assert_eq!(FsError::PathTooLong.to_errno(), -36);
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/test/file").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("../etc/passwd").is_err());
    }

    #[test]
    fn test_normalize_path() {
        use super::path::normalize_path;
        assert_eq!(normalize_path("/a/b/c"), "/a/b/c");
        assert_eq!(normalize_path("/a//b/./c"), "/a/b/c");
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("a/b/c"), "a/b/c");
    }

    #[test]
    fn test_secure_zeroize() {
        let mut data = [0xFFu8; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
