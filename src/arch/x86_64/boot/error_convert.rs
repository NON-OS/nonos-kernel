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

use super::error_types::BootError;

impl BootError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error", Self::SerialInitFailed => "serial port initialization failed",
            Self::VgaInitFailed => "VGA display initialization failed",
            Self::CpuInitFailed => "CPU detection/initialization failed",
            Self::NoCpuid => "CPUID instruction not available",
            Self::NoLongMode => "long mode (x86_64) not supported",
            Self::NoSse => "SSE not supported (required for x86_64)",
            Self::NoSse2 => "SSE2 not supported (required for x86_64)",
            Self::NoFxsr => "FXSAVE/FXRSTOR not supported", Self::NoApic => "APIC not available",
            Self::NoMsr => "MSR instructions not supported", Self::NoPae => "PAE not supported",
            Self::GdtInitFailed => "GDT initialization failed", Self::GdtLoadFailed => "failed to load GDT",
            Self::TssLoadFailed => "failed to load TSS", Self::IdtInitFailed => "IDT initialization failed",
            Self::IdtLoadFailed => "failed to load IDT", Self::SseEnableFailed => "SSE/AVX enablement failed",
            Self::InvalidPageTable => "invalid page table (CR3 = 0)",
            Self::PagingNotEnabled => "paging not enabled in CR0", Self::PaeNotEnabled => "PAE not enabled in CR4",
            Self::LongModeNotActive => "long mode not active in EFER",
            Self::NoHigherHalf => "higher-half kernel mapping not present",
            Self::MemoryValidationFailed => "memory validation failed",
            Self::StackSetupFailed => "interrupt stack setup failed", Self::Timeout => "boot sequence timeout",
            Self::NoSmap => "SMAP not supported", Self::NoSmep => "SMEP not supported",
            Self::NoNx => "NX bit not supported", Self::ApicInitFailed => "APIC initialization failed",
            Self::TimerInitFailed => "timer initialization failed", Self::AcpiInitFailed => "ACPI initialization failed",
            Self::Unknown => "unknown boot error",
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None, 1 => Self::SerialInitFailed, 2 => Self::VgaInitFailed, 3 => Self::CpuInitFailed,
            4 => Self::NoCpuid, 5 => Self::NoLongMode, 6 => Self::NoSse, 7 => Self::NoSse2, 8 => Self::NoFxsr,
            9 => Self::NoApic, 10 => Self::NoMsr, 11 => Self::NoPae, 12 => Self::GdtInitFailed,
            13 => Self::GdtLoadFailed, 14 => Self::TssLoadFailed, 15 => Self::IdtInitFailed,
            16 => Self::IdtLoadFailed, 17 => Self::SseEnableFailed, 18 => Self::InvalidPageTable,
            19 => Self::PagingNotEnabled, 20 => Self::PaeNotEnabled, 21 => Self::LongModeNotActive,
            22 => Self::NoHigherHalf, 23 => Self::MemoryValidationFailed, 24 => Self::StackSetupFailed,
            25 => Self::Timeout, 26 => Self::NoSmap, 27 => Self::NoSmep, 28 => Self::NoNx,
            29 => Self::ApicInitFailed, 30 => Self::TimerInitFailed, 31 => Self::AcpiInitFailed, _ => Self::Unknown,
        }
    }
}
