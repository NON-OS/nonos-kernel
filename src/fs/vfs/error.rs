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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotInitialized,
    NotFound,
    AlreadyExists,
    PathTooLong,
    InvalidPath,
    TooManyOpenFiles,
    InvalidFd,
    NotReadable,
    NotWritable,
    InvalidSeek,
    DirectoryNotEmpty,
    NotADirectory,
    IsADirectory,
    PermissionDenied,
    FsError(&'static str),
    IoError(&'static str),
}

impl VfsError {
    pub const fn to_errno(self) -> i32 {
        match self {
            VfsError::NotInitialized => -5,
            VfsError::NotFound => -2,
            VfsError::AlreadyExists => -17,
            VfsError::PathTooLong => -36,
            VfsError::InvalidPath => -22,
            VfsError::TooManyOpenFiles => -24,
            VfsError::InvalidFd => -9,
            VfsError::NotReadable => -9,
            VfsError::NotWritable => -9,
            VfsError::InvalidSeek => -22,
            VfsError::DirectoryNotEmpty => -39,
            VfsError::NotADirectory => -20,
            VfsError::IsADirectory => -21,
            VfsError::PermissionDenied => -13,
            VfsError::FsError(_) => -5,
            VfsError::IoError(_) => -5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            VfsError::NotInitialized => "VFS not initialized",
            VfsError::NotFound => "File not found",
            VfsError::AlreadyExists => "File already exists",
            VfsError::PathTooLong => "Path too long",
            VfsError::InvalidPath => "Invalid path",
            VfsError::TooManyOpenFiles => "Too many open files",
            VfsError::InvalidFd => "Invalid file descriptor",
            VfsError::NotReadable => "File not open for reading",
            VfsError::NotWritable => "File not open for writing",
            VfsError::InvalidSeek => "Invalid seek position",
            VfsError::DirectoryNotEmpty => "Directory not empty",
            VfsError::NotADirectory => "Not a directory",
            VfsError::IsADirectory => "Is a directory",
            VfsError::PermissionDenied => "Permission denied",
            VfsError::FsError(msg) => msg,
            VfsError::IoError(msg) => msg,
        }
    }
}

impl VfsError {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }
}

impl From<VfsError> for &'static str {
    fn from(err: VfsError) -> Self {
        err.as_str()
    }
}

impl From<crate::fs::ramfs::FsError> for VfsError {
    fn from(err: crate::fs::ramfs::FsError) -> Self {
        VfsError::FsError(err.as_str())
    }
}

pub type VfsResult<T> = Result<T, VfsError>;
