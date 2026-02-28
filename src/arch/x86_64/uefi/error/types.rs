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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UefiError {
    NotInitialized,

    AlreadyInitialized,

    RuntimeServicesNotAvailable,

    BootServicesExited,

    VariableNotFound {
        name: &'static str,
    },

    VariableWriteFailed {
        status: u64,
    },

    VariableReadFailed {
        status: u64,
    },

    InvalidSignature {
        expected: u64,
        found: u64,
    },

    CrcMismatch {
        expected: u32,
        computed: u32,
    },

    SecureBootFailed,

    NotInSetupMode,

    InvalidGuid,

    BufferTooSmall {
        required: usize,
        provided: usize,
    },

    AccessDenied,

    WriteProtected,

    SecurityViolation,

    OutOfResources,

    InvalidParameter {
        param: &'static str,
    },

    SignatureListParseError {
        offset: usize,
    },

    HashNotInDatabase,

    HashRevoked,

    AllocationFailed {
        size: usize,
    },

    NullPointer {
        context: &'static str,
    },

    Timeout {
        operation: &'static str,
    },

    UnsupportedRevision {
        minimum: u32,
        actual: u32,
    },

    ProtocolNotFound {
        protocol: &'static str,
    },

    VariableNameTooLong {
        length: usize,
        max_length: usize,
    },

    VariableDataTooLarge {
        size: usize,
        max_size: usize,
    },
}

pub type UefiResult<T> = Result<T, UefiError>;
