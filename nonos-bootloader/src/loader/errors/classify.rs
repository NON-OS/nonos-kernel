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

use super::error::LoaderError;

impl LoaderError {
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            LoaderError::KernelTooLarge
                | LoaderError::WxViolation
                | LoaderError::MalformedElf(_)
                | LoaderError::SignatureInvalid
                | LoaderError::HashMismatch
                | LoaderError::AddressOutOfRange
                | LoaderError::IntegerOverflow
        )
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            LoaderError::SignatureInvalid
                | LoaderError::HashMismatch
                | LoaderError::CapsuleSignatureFailed
                | LoaderError::MalformedElf(_)
        )
    }

    pub fn category(&self) -> &'static str {
        match self {
            LoaderError::InvalidMagic
            | LoaderError::InvalidClass
            | LoaderError::InvalidEndian
            | LoaderError::InvalidVersion
            | LoaderError::ElfParseError(_)
            | LoaderError::UnsupportedElf(_) => "parse",

            LoaderError::NoLoadableSegments
            | LoaderError::TooManySegments
            | LoaderError::SegmentOutOfBounds
            | LoaderError::SegmentOverlap
            | LoaderError::InvalidSegmentSize
            | LoaderError::InvalidSegmentAlignment => "segment",

            LoaderError::AllocationFailed { .. }
            | LoaderError::AllocationTableFull
            | LoaderError::OutOfMemory => "memory",

            LoaderError::KernelTooLarge
            | LoaderError::WxViolation
            | LoaderError::MalformedElf(_)
            | LoaderError::SignatureInvalid
            | LoaderError::HashMismatch
            | LoaderError::AddressOutOfRange
            | LoaderError::IntegerOverflow => "security",

            LoaderError::CapsuleInvalid | LoaderError::CapsuleSignatureFailed => "capsule",

            LoaderError::RelocationFailed(_)
            | LoaderError::UnsupportedRelocation(_)
            | LoaderError::SymbolNotFound => "relocation",

            LoaderError::UefiError { .. } | LoaderError::BootServicesUnavailable => "uefi",

            LoaderError::InvalidDynamic | LoaderError::MissingDynamicInfo => "dynamic",

            LoaderError::EntryNotInRange => "entry",

            LoaderError::FileNotFound | LoaderError::FileReadError | LoaderError::FileTooLarge => {
                "file"
            }
        }
    }
}
