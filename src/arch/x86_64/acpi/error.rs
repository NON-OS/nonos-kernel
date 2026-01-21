// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
#[repr(u8)]
pub enum AcpiError {
    NotInitialized = 0,
    AlreadyInitialized = 1,
    RsdpNotFound = 2,
    InvalidRsdpSignature = 3,
    RsdpChecksumFailed = 4,
    ExtendedRsdpChecksumFailed = 5,
    NoRootTable = 6,
    InvalidRsdtSignature = 7,
    RsdtChecksumFailed = 8,
    InvalidXsdtSignature = 9,
    XsdtChecksumFailed = 10,
    TableNotFound = 11,
    InvalidTableSignature = 12,
    TableChecksumFailed = 13,
    InvalidTableStructure = 14,
    FadtNotFound = 15,
    MadtNotFound = 16,
    PowerStateNotSupported = 17,
    HardwareAccessFailed = 18,
    ResetNotAvailable = 19,
    InvalidAddress = 20,
    UnsupportedRevision = 21,
}

impl AcpiError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "ACPI not initialized",
            Self::AlreadyInitialized => "ACPI already initialized",
            Self::RsdpNotFound => "RSDP not found",
            Self::InvalidRsdpSignature => "invalid RSDP signature",
            Self::RsdpChecksumFailed => "RSDP checksum failed",
            Self::ExtendedRsdpChecksumFailed => "extended RSDP checksum failed",
            Self::NoRootTable => "no root table",
            Self::InvalidRsdtSignature => "invalid RSDT signature",
            Self::RsdtChecksumFailed => "RSDT checksum failed",
            Self::InvalidXsdtSignature => "invalid XSDT signature",
            Self::XsdtChecksumFailed => "XSDT checksum failed",
            Self::TableNotFound => "table not found",
            Self::InvalidTableSignature => "invalid table signature",
            Self::TableChecksumFailed => "table checksum failed",
            Self::InvalidTableStructure => "invalid table structure",
            Self::FadtNotFound => "FADT not found",
            Self::MadtNotFound => "MADT not found",
            Self::PowerStateNotSupported => "power state not supported",
            Self::HardwareAccessFailed => "hardware access failed",
            Self::ResetNotAvailable => "reset not available",
            Self::InvalidAddress => "invalid address",
            Self::UnsupportedRevision => "unsupported revision",
        }
    }
}

impl core::fmt::Display for AcpiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type AcpiResult<T> = Result<T, AcpiError>;
