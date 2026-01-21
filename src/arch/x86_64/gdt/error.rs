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
pub enum GdtError {
    None = 0,
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidSelector = 3,
    InvalidCpuId = 4,
    InvalidIstIndex = 5,
    InvalidRspIndex = 6,
    TssNotConfigured = 7,
    StackAllocationFailed = 8,
    LoadFailed = 9,
    TssLoadFailed = 10,
    SegmentReloadFailed = 11,
    MsrWriteFailed = 12,
}

impl GdtError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "GDT not initialized",
            Self::AlreadyInitialized => "GDT already initialized",
            Self::InvalidSelector => "invalid segment selector",
            Self::InvalidCpuId => "invalid CPU ID",
            Self::InvalidIstIndex => "IST index must be 1-7",
            Self::InvalidRspIndex => "RSP index must be 0-2",
            Self::TssNotConfigured => "TSS not configured",
            Self::StackAllocationFailed => "interrupt stack allocation failed",
            Self::LoadFailed => "GDT load failed",
            Self::TssLoadFailed => "TSS load failed",
            Self::SegmentReloadFailed => "segment register reload failed",
            Self::MsrWriteFailed => "MSR write failed",
        }
    }
}
