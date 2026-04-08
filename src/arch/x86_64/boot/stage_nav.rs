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

use super::stage_enum::BootStage;

impl BootStage {
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Entry => Some(Self::SerialInit),
            Self::SerialInit => Some(Self::VgaInit),
            Self::VgaInit => Some(Self::CpuDetect),
            Self::CpuDetect => Some(Self::GdtSetup),
            Self::GdtSetup => Some(Self::SegmentReload),
            Self::SegmentReload => Some(Self::SseEnable),
            Self::SseEnable => Some(Self::IdtSetup),
            Self::IdtSetup => Some(Self::MemoryValidation),
            Self::MemoryValidation => Some(Self::KernelTransfer),
            Self::KernelTransfer => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    pub const fn prev(self) -> Option<Self> {
        match self {
            Self::Entry => None,
            Self::SerialInit => Some(Self::Entry),
            Self::VgaInit => Some(Self::SerialInit),
            Self::CpuDetect => Some(Self::VgaInit),
            Self::GdtSetup => Some(Self::CpuDetect),
            Self::SegmentReload => Some(Self::GdtSetup),
            Self::SseEnable => Some(Self::SegmentReload),
            Self::IdtSetup => Some(Self::SseEnable),
            Self::MemoryValidation => Some(Self::IdtSetup),
            Self::KernelTransfer => Some(Self::MemoryValidation),
            Self::Complete => Some(Self::KernelTransfer),
        }
    }
}
