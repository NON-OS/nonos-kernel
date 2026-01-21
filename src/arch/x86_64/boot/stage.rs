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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BootStage {
    Entry = 0,
    SerialInit = 1,
    VgaInit = 2,
    CpuDetect = 3,
    GdtSetup = 4,
    SegmentReload = 5,
    SseEnable = 6,
    IdtSetup = 7,
    MemoryValidation = 8,
    KernelTransfer = 9,
    Complete = 10,
}

impl BootStage {
    pub const COUNT: usize = 11;

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

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_early(self) -> bool {
        matches!(self, Self::Entry | Self::SerialInit | Self::VgaInit | Self::CpuDetect)
    }

    pub const fn has_interrupts(self) -> bool {
        matches!(
            self,
            Self::IdtSetup | Self::MemoryValidation | Self::KernelTransfer | Self::Complete
        )
    }

    pub fn all() -> impl Iterator<Item = Self> {
        (0..Self::COUNT).map(|i| Self::from_u8(i as u8))
    }
}

impl Default for BootStage {
    fn default() -> Self {
        Self::Entry
    }
}

impl core::fmt::Display for BootStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_names() {
        assert_eq!(BootStage::Entry.as_str(), "Entry");
        assert_eq!(BootStage::Complete.as_str(), "Complete");
    }

    #[test]
    fn test_stage_from_u8() {
        assert_eq!(BootStage::from_u8(0), BootStage::Entry);
        assert_eq!(BootStage::from_u8(10), BootStage::Complete);
        assert_eq!(BootStage::from_u8(100), BootStage::Complete);
    }

    #[test]
    fn test_stage_ordering() {
        assert!(BootStage::Entry < BootStage::SerialInit);
        assert!(BootStage::SerialInit < BootStage::Complete);
    }

    #[test]
    fn test_stage_next() {
        assert_eq!(BootStage::Entry.next(), Some(BootStage::SerialInit));
        assert_eq!(BootStage::KernelTransfer.next(), Some(BootStage::Complete));
        assert_eq!(BootStage::Complete.next(), None);
    }

    #[test]
    fn test_stage_prev() {
        assert_eq!(BootStage::Entry.prev(), None);
        assert_eq!(BootStage::SerialInit.prev(), Some(BootStage::Entry));
        assert_eq!(BootStage::Complete.prev(), Some(BootStage::KernelTransfer));
    }

    #[test]
    fn test_is_complete() {
        assert!(!BootStage::Entry.is_complete());
        assert!(BootStage::Complete.is_complete());
    }

    #[test]
    fn test_is_early() {
        assert!(BootStage::Entry.is_early());
        assert!(BootStage::CpuDetect.is_early());
        assert!(!BootStage::IdtSetup.is_early());
    }

    #[test]
    fn test_has_interrupts() {
        assert!(!BootStage::Entry.has_interrupts());
        assert!(BootStage::IdtSetup.has_interrupts());
        assert!(BootStage::Complete.has_interrupts());
    }

    #[test]
    fn test_all_stages() {
        let stages: Vec<BootStage> = BootStage::all().collect();
        assert_eq!(stages.len(), BootStage::COUNT);
        assert_eq!(stages[0], BootStage::Entry);
        assert_eq!(stages[10], BootStage::Complete);
    }

    #[test]
    fn test_count() {
        assert_eq!(BootStage::COUNT, 11);
    }
}
