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
pub enum BootError {
    None = 0,
    SerialInitFailed = 1,
    VgaInitFailed = 2,
    CpuInitFailed = 3,
    NoCpuid = 4,
    NoLongMode = 5,
    NoSse = 6,
    NoSse2 = 7,
    NoFxsr = 8,
    NoApic = 9,
    NoMsr = 10,
    NoPae = 11,
    GdtInitFailed = 12,
    GdtLoadFailed = 13,
    TssLoadFailed = 14,
    IdtInitFailed = 15,
    IdtLoadFailed = 16,
    SseEnableFailed = 17,
    InvalidPageTable = 18,
    PagingNotEnabled = 19,
    PaeNotEnabled = 20,
    LongModeNotActive = 21,
    NoHigherHalf = 22,
    MemoryValidationFailed = 23,
    StackSetupFailed = 24,
    Timeout = 25,
    NoSmap = 26,
    NoSmep = 27,
    NoNx = 28,
    ApicInitFailed = 29,
    TimerInitFailed = 30,
    AcpiInitFailed = 31,
    Unknown = 255,
}

impl BootError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::SerialInitFailed => "serial port initialization failed",
            Self::VgaInitFailed => "VGA display initialization failed",
            Self::CpuInitFailed => "CPU detection/initialization failed",
            Self::NoCpuid => "CPUID instruction not available",
            Self::NoLongMode => "long mode (x86_64) not supported",
            Self::NoSse => "SSE not supported (required for x86_64)",
            Self::NoSse2 => "SSE2 not supported (required for x86_64)",
            Self::NoFxsr => "FXSAVE/FXRSTOR not supported",
            Self::NoApic => "APIC not available",
            Self::NoMsr => "MSR instructions not supported",
            Self::NoPae => "PAE not supported",
            Self::GdtInitFailed => "GDT initialization failed",
            Self::GdtLoadFailed => "failed to load GDT",
            Self::TssLoadFailed => "failed to load TSS",
            Self::IdtInitFailed => "IDT initialization failed",
            Self::IdtLoadFailed => "failed to load IDT",
            Self::SseEnableFailed => "SSE/AVX enablement failed",
            Self::InvalidPageTable => "invalid page table (CR3 = 0)",
            Self::PagingNotEnabled => "paging not enabled in CR0",
            Self::PaeNotEnabled => "PAE not enabled in CR4",
            Self::LongModeNotActive => "long mode not active in EFER",
            Self::NoHigherHalf => "higher-half kernel mapping not present",
            Self::MemoryValidationFailed => "memory validation failed",
            Self::StackSetupFailed => "interrupt stack setup failed",
            Self::Timeout => "boot sequence timeout",
            Self::NoSmap => "SMAP not supported",
            Self::NoSmep => "SMEP not supported",
            Self::NoNx => "NX bit not supported",
            Self::ApicInitFailed => "APIC initialization failed",
            Self::TimerInitFailed => "timer initialization failed",
            Self::AcpiInitFailed => "ACPI initialization failed",
            Self::Unknown => "unknown boot error",
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::SerialInitFailed,
            2 => Self::VgaInitFailed,
            3 => Self::CpuInitFailed,
            4 => Self::NoCpuid,
            5 => Self::NoLongMode,
            6 => Self::NoSse,
            7 => Self::NoSse2,
            8 => Self::NoFxsr,
            9 => Self::NoApic,
            10 => Self::NoMsr,
            11 => Self::NoPae,
            12 => Self::GdtInitFailed,
            13 => Self::GdtLoadFailed,
            14 => Self::TssLoadFailed,
            15 => Self::IdtInitFailed,
            16 => Self::IdtLoadFailed,
            17 => Self::SseEnableFailed,
            18 => Self::InvalidPageTable,
            19 => Self::PagingNotEnabled,
            20 => Self::PaeNotEnabled,
            21 => Self::LongModeNotActive,
            22 => Self::NoHigherHalf,
            23 => Self::MemoryValidationFailed,
            24 => Self::StackSetupFailed,
            25 => Self::Timeout,
            26 => Self::NoSmap,
            27 => Self::NoSmep,
            28 => Self::NoNx,
            29 => Self::ApicInitFailed,
            30 => Self::TimerInitFailed,
            31 => Self::AcpiInitFailed,
            _ => Self::Unknown,
        }
    }

    pub const fn is_fatal(self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn is_cpu_related(self) -> bool {
        matches!(
            self,
            Self::CpuInitFailed
                | Self::NoCpuid
                | Self::NoLongMode
                | Self::NoSse
                | Self::NoSse2
                | Self::NoFxsr
                | Self::NoApic
                | Self::NoMsr
                | Self::NoPae
                | Self::NoSmap
                | Self::NoSmep
                | Self::NoNx
        )
    }

    pub const fn is_memory_related(self) -> bool {
        matches!(
            self,
            Self::InvalidPageTable
                | Self::PagingNotEnabled
                | Self::PaeNotEnabled
                | Self::LongModeNotActive
                | Self::NoHigherHalf
                | Self::MemoryValidationFailed
                | Self::StackSetupFailed
        )
    }
}

impl Default for BootError {
    fn default() -> Self {
        Self::None
    }
}

impl core::fmt::Display for BootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(BootError::None.as_str(), "no error");
        assert_eq!(BootError::NoSse.as_str(), "SSE not supported (required for x86_64)");
        assert_eq!(BootError::InvalidPageTable.as_str(), "invalid page table (CR3 = 0)");
    }

    #[test]
    fn test_error_from_u8() {
        assert_eq!(BootError::from_u8(0), BootError::None);
        assert_eq!(BootError::from_u8(6), BootError::NoSse);
        assert_eq!(BootError::from_u8(255), BootError::Unknown);
        assert_eq!(BootError::from_u8(200), BootError::Unknown);
    }

    #[test]
    fn test_is_fatal() {
        assert!(!BootError::None.is_fatal());
        assert!(BootError::NoSse.is_fatal());
        assert!(BootError::Unknown.is_fatal());
    }

    #[test]
    fn test_is_cpu_related() {
        assert!(BootError::NoCpuid.is_cpu_related());
        assert!(BootError::NoSse.is_cpu_related());
        assert!(!BootError::InvalidPageTable.is_cpu_related());
    }

    #[test]
    fn test_is_memory_related() {
        assert!(BootError::InvalidPageTable.is_memory_related());
        assert!(BootError::PagingNotEnabled.is_memory_related());
        assert!(!BootError::NoSse.is_memory_related());
    }

    #[test]
    fn test_default() {
        assert_eq!(BootError::default(), BootError::None);
    }
}
