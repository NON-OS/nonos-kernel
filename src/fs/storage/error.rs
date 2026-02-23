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
pub enum StorageError {
    NotInitialized,
    QuotaExceeded,
    InodeExhausted,
    StorageFull,
    AllocationFailed,
    InvalidSize,
    FragmentationHigh,
    HealthCheckFailed,
    StatisticsUnavailable,
}

impl StorageError {
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::NotInitialized => -5,
            Self::QuotaExceeded => -122,
            Self::InodeExhausted => -28,
            Self::StorageFull => -28,
            Self::AllocationFailed => -12,
            Self::InvalidSize => -22,
            Self::FragmentationHigh => -5,
            Self::HealthCheckFailed => -5,
            Self::StatisticsUnavailable => -5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "Storage not initialized",
            Self::QuotaExceeded => "Quota exceeded",
            Self::InodeExhausted => "Inode exhausted",
            Self::StorageFull => "Storage full",
            Self::AllocationFailed => "Allocation failed",
            Self::InvalidSize => "Invalid size",
            Self::FragmentationHigh => "High fragmentation",
            Self::HealthCheckFailed => "Health check failed",
            Self::StatisticsUnavailable => "Statistics unavailable",
        }
    }
}

impl From<StorageError> for &'static str {
    fn from(err: StorageError) -> Self {
        err.as_str()
    }
}

pub type StorageResult<T> = Result<T, StorageError>;
