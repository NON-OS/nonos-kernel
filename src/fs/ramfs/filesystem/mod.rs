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

mod path;
mod key;
mod crypto;
mod fs;
mod global;
mod legacy;

pub use path::normalize_path;
pub use fs::NonosFilesystem;
pub use global::{
    NONOS_FILESYSTEM,
    init_nonos_filesystem,
    get_filesystem,
    create_file,
    read_file,
    write_file,
    delete_file,
    list_files,
    exists,
    file_exists,
    dir_exists,
    list_dir,
    list_dir_entries,
    create_dir,
    delete,
    rename,
    stats,
    init_nonos_fs,
};

#[cfg(test)]
mod tests {
    use super::*;
    use super::path::validate_path;
    use super::super::error::FsError;
    use super::super::types::secure_zeroize;

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
