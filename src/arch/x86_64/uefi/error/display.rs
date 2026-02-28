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

use core::fmt;

use crate::arch::x86_64::uefi::constants::status;
use super::types::UefiError;

impl fmt::Display for UefiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UefiError::VariableNotFound { name } => {
                write!(f, "UEFI variable not found: {}", name)
            }
            UefiError::VariableWriteFailed { status: s } => {
                write!(
                    f,
                    "UEFI variable write failed: {} (0x{:x})",
                    status::name(*s),
                    s
                )
            }
            UefiError::VariableReadFailed { status: s } => {
                write!(
                    f,
                    "UEFI variable read failed: {} (0x{:x})",
                    status::name(*s),
                    s
                )
            }
            UefiError::InvalidSignature { expected, found } => {
                write!(
                    f,
                    "Invalid table signature: expected 0x{:016x}, found 0x{:016x}",
                    expected, found
                )
            }
            UefiError::CrcMismatch { expected, computed } => {
                write!(
                    f,
                    "CRC mismatch: expected 0x{:08x}, computed 0x{:08x}",
                    expected, computed
                )
            }
            UefiError::BufferTooSmall { required, provided } => {
                write!(
                    f,
                    "Buffer too small: required {} bytes, provided {} bytes",
                    required, provided
                )
            }
            UefiError::InvalidParameter { param } => {
                write!(f, "Invalid parameter: {}", param)
            }
            UefiError::SignatureListParseError { offset } => {
                write!(f, "Signature list parse error at offset 0x{:x}", offset)
            }
            UefiError::AllocationFailed { size } => {
                write!(f, "Memory allocation failed for {} bytes", size)
            }
            UefiError::NullPointer { context } => {
                write!(f, "Null pointer: {}", context)
            }
            UefiError::Timeout { operation } => {
                write!(f, "Operation timed out: {}", operation)
            }
            UefiError::UnsupportedRevision { minimum, actual } => {
                write!(
                    f,
                    "Unsupported revision: minimum 0x{:08x}, actual 0x{:08x}",
                    minimum, actual
                )
            }
            UefiError::ProtocolNotFound { protocol } => {
                write!(f, "Protocol not found: {}", protocol)
            }
            UefiError::VariableNameTooLong { length, max_length } => {
                write!(
                    f,
                    "Variable name too long: {} chars, max {} chars",
                    length, max_length
                )
            }
            UefiError::VariableDataTooLarge { size, max_size } => {
                write!(
                    f,
                    "Variable data too large: {} bytes, max {} bytes",
                    size, max_size
                )
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}
