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
pub enum FsSubsystemError {
    VfsNotInitialized,
    CryptoFsNotInitialized,
    ManagerNotInitialized,
    PageCacheError,
    InodeCacheError,
    DentryCacheError,
    WritebackError,
    StorageDeviceError,
    FilesystemFull,
    SuperblockCorrupted,
    InodeTableCorrupted,
    InternalError(&'static str),
}

impl FsSubsystemError {
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::VfsNotInitialized | Self::CryptoFsNotInitialized |
            Self::ManagerNotInitialized | Self::WritebackError |
            Self::StorageDeviceError | Self::SuperblockCorrupted |
            Self::InodeTableCorrupted | Self::InternalError(_) => -5,
            Self::PageCacheError | Self::InodeCacheError |
            Self::DentryCacheError => -12,
            Self::FilesystemFull => -28,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VfsNotInitialized => "VFS not initialized",
            Self::CryptoFsNotInitialized => "CryptoFS not initialized",
            Self::ManagerNotInitialized => "Filesystem manager not initialized",
            Self::PageCacheError => "Page cache error",
            Self::InodeCacheError => "Inode cache error",
            Self::DentryCacheError => "Dentry cache error",
            Self::WritebackError => "Writeback error",
            Self::StorageDeviceError => "Storage device error",
            Self::FilesystemFull => "Filesystem full",
            Self::SuperblockCorrupted => "Superblock corrupted",
            Self::InodeTableCorrupted => "Inode table corrupted",
            Self::InternalError(msg) => msg,
        }
    }
}

impl From<FsSubsystemError> for &'static str {
    fn from(err: FsSubsystemError) -> Self {
        err.as_str()
    }
}

pub type FsSubsystemResult<T> = Result<T, FsSubsystemError>;
