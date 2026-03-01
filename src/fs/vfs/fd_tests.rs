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

use super::error::VfsError;
use super::types::OpenFlags;

#[test]
fn test_vfs_error_to_errno() {
    assert_eq!(VfsError::NotFound.to_errno(), -2);
    assert_eq!(VfsError::InvalidFd.to_errno(), -9);
    assert_eq!(VfsError::TooManyOpenFiles.to_errno(), -24);
}

#[test]
fn test_open_flags() {
    let flags = OpenFlags::READ | OpenFlags::WRITE;
    assert!(flags.is_readable());
    assert!(flags.is_writable());
    assert!(flags.contains(OpenFlags::READ));
    assert!(flags.contains(OpenFlags::WRITE));
    assert!(!flags.contains(OpenFlags::CREATE));
}
