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
pub enum IoApicError {
    NotInitialized,
    AlreadyInitialized,
    GsiNotFound,
    GsiClaimedForMsi,
    VectorExhausted,
    MmioMapFailed,
    InvalidGsi,
    TooManyIoApics,
}

impl IoApicError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "I/O APIC not initialized",
            Self::AlreadyInitialized => "I/O APIC already initialized",
            Self::GsiNotFound => "GSI not found",
            Self::GsiClaimedForMsi => "GSI claimed for MSI",
            Self::VectorExhausted => "No vectors available",
            Self::MmioMapFailed => "MMIO mapping failed",
            Self::InvalidGsi => "Invalid GSI",
            Self::TooManyIoApics => "Too many I/O APICs",
        }
    }
}

pub type IoApicResult<T> = Result<T, IoApicError>;
