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

pub use super::stage_enum::BootStage;

#[cfg(all(test, not(feature = "std")))]
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
}
