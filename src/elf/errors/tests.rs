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

extern crate alloc;

use super::*;

#[test]
fn test_error_as_str() {
    let e = ElfError::InvalidMagic;
    assert_eq!(e.as_str(), "Invalid ELF magic number");

    let e = ElfError::Other("custom error");
    assert_eq!(e.as_str(), "custom error");
}

#[test]
fn test_error_display() {
    let e = ElfError::InvalidMagic;
    let s = alloc::format!("{}", e);
    assert!(s.contains("magic"));

    let e = ElfError::UnsupportedRelocation(42);
    let s = alloc::format!("{}", e);
    assert!(s.contains("42"));
}

#[test]
fn test_error_from_str() {
    let e: ElfError = "test error".into();
    assert_eq!(e, ElfError::Other("test error"));
}

#[test]
fn test_is_validation_error() {
    assert!(ElfError::InvalidMagic.is_validation_error());
    assert!(ElfError::InvalidClass.is_validation_error());
    assert!(ElfError::InvalidMachine.is_validation_error());
    assert!(!ElfError::FileTooSmall.is_validation_error());
    assert!(!ElfError::MemoryAllocationFailed.is_validation_error());
}

#[test]
fn test_is_bounds_error() {
    assert!(ElfError::FileTooSmall.is_bounds_error());
    assert!(ElfError::ProgramHeadersOutOfBounds.is_bounds_error());
    assert!(ElfError::SegmentDataOutOfBounds.is_bounds_error());
    assert!(!ElfError::InvalidMagic.is_bounds_error());
}

#[test]
fn test_is_memory_error() {
    assert!(ElfError::MemoryAllocationFailed.is_memory_error());
    assert!(ElfError::MemoryMappingFailed.is_memory_error());
    assert!(ElfError::AddressOverflow.is_memory_error());
    assert!(!ElfError::InvalidMagic.is_memory_error());
}

#[test]
fn test_is_dynamic_error() {
    assert!(ElfError::RelocationFailed.is_dynamic_error());
    assert!(ElfError::SymbolNotFound.is_dynamic_error());
    assert!(ElfError::UnsupportedRelocation(0).is_dynamic_error());
    assert!(!ElfError::InvalidMagic.is_dynamic_error());
}

#[test]
fn test_error_equality() {
    assert_eq!(ElfError::InvalidMagic, ElfError::InvalidMagic);
    assert_ne!(ElfError::InvalidMagic, ElfError::InvalidClass);
    assert_eq!(
        ElfError::UnsupportedRelocation(5),
        ElfError::UnsupportedRelocation(5)
    );
    assert_ne!(
        ElfError::UnsupportedRelocation(5),
        ElfError::UnsupportedRelocation(6)
    );
}
