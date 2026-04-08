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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "Entry",
            Self::SerialInit => "Serial Init",
            Self::VgaInit => "VGA Init",
            Self::CpuDetect => "CPU Detection",
            Self::GdtSetup => "GDT/TSS Setup",
            Self::SegmentReload => "Segment Reload",
            Self::SseEnable => "SSE/AVX Enable",
            Self::IdtSetup => "IDT Setup",
            Self::MemoryValidation => "Memory Validation",
            Self::KernelTransfer => "Kernel Transfer",
            Self::Complete => "Complete",
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Entry,
            1 => Self::SerialInit,
            2 => Self::VgaInit,
            3 => Self::CpuDetect,
            4 => Self::GdtSetup,
            5 => Self::SegmentReload,
            6 => Self::SseEnable,
            7 => Self::IdtSetup,
            8 => Self::MemoryValidation,
            9 => Self::KernelTransfer,
            _ => Self::Complete,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}
