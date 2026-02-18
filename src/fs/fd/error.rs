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
pub enum FdError {
    InvalidFd,
    NotOpen,
    NullPointer,
    PathTooLong,
    InvalidUtf8,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    NotReadable,
    NotWritable,
    InvalidWhence,
    StdioOperation,
    NoFdsAvailable,
    VfsNotInitialized,
    FsError(&'static str),
    FilesystemError(crate::fs::ramfs::FsError),
    InvalidArgument,
    BufferTooLarge,
    WouldBlock,
}

impl FdError {
    pub fn to_errno(self) -> i32 {
        match self {
            FdError::InvalidFd => -9,
            FdError::NotOpen => -9,
            FdError::NullPointer => -14,
            FdError::PathTooLong => -36,
            FdError::InvalidUtf8 => -22,
            FdError::NotFound => -2,
            FdError::AlreadyExists => -17,
            FdError::PermissionDenied => -13,
            FdError::NotReadable => -9,
            FdError::NotWritable => -9,
            FdError::InvalidWhence => -22,
            FdError::StdioOperation => -22,
            FdError::NoFdsAvailable => -24,
            FdError::VfsNotInitialized => -5,
            FdError::FsError(_) => -5,
            FdError::FilesystemError(e) => e.to_errno(),
            FdError::InvalidArgument => -22,
            FdError::BufferTooLarge => -22,
            FdError::WouldBlock => -11,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FdError::InvalidFd => "Invalid file descriptor",
            FdError::NotOpen => "File descriptor not open",
            FdError::NullPointer => "Null pointer",
            FdError::PathTooLong => "Path too long",
            FdError::InvalidUtf8 => "Invalid UTF-8 in path",
            FdError::NotFound => "File not found",
            FdError::AlreadyExists => "File already exists",
            FdError::PermissionDenied => "Permission denied",
            FdError::NotReadable => "File not open for reading",
            FdError::NotWritable => "File not open for writing",
            FdError::InvalidWhence => "Invalid seek whence",
            FdError::StdioOperation => "Cannot perform operation on stdio",
            FdError::NoFdsAvailable => "No file descriptors available",
            FdError::VfsNotInitialized => "VFS not initialized",
            FdError::FsError(msg) => msg,
            FdError::FilesystemError(e) => e.as_str(),
            FdError::InvalidArgument => "Invalid argument",
            FdError::BufferTooLarge => "Buffer too large",
            FdError::WouldBlock => "Operation would block",
        }
    }
}

impl From<crate::fs::ramfs::FsError> for FdError {
    fn from(err: crate::fs::ramfs::FsError) -> Self {
        FdError::FilesystemError(err)
    }
}

impl From<&'static str> for FdError {
    fn from(msg: &'static str) -> Self {
        FdError::FsError(msg)
    }
}

impl From<crate::fs::vfs::VfsError> for FdError {
    fn from(err: crate::fs::vfs::VfsError) -> Self {
        FdError::FsError(err.as_str())
    }
}

impl From<FdError> for &'static str {
    fn from(err: FdError) -> Self {
        err.as_str()
    }
}

pub type FdResult<T> = Result<T, FdError>;
