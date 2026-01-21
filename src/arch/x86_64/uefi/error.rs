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

use super::constants::status;
use core::fmt;

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

impl UefiError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            UefiError::NotInitialized => "UEFI not initialized",
            UefiError::AlreadyInitialized => "UEFI already initialized",
            UefiError::RuntimeServicesNotAvailable => "UEFI runtime services not available",
            UefiError::BootServicesExited => "UEFI boot services have exited",
            UefiError::VariableNotFound { .. } => "UEFI variable not found",
            UefiError::VariableWriteFailed { .. } => "UEFI variable write failed",
            UefiError::VariableReadFailed { .. } => "UEFI variable read failed",
            UefiError::InvalidSignature { .. } => "Invalid table signature",
            UefiError::CrcMismatch { .. } => "Table CRC32 verification failed",
            UefiError::SecureBootFailed => "Secure Boot validation failed",
            UefiError::NotInSetupMode => "Not in UEFI Setup Mode",
            UefiError::InvalidGuid => "Invalid GUID format",
            UefiError::BufferTooSmall { .. } => "Buffer too small for data",
            UefiError::AccessDenied => "Access denied to UEFI variable",
            UefiError::WriteProtected => "Variable is write protected",
            UefiError::SecurityViolation => "Security policy violation",
            UefiError::OutOfResources => "Out of resources",
            UefiError::InvalidParameter { .. } => "Invalid parameter",
            UefiError::SignatureListParseError { .. } => "Failed to parse signature list",
            UefiError::HashNotInDatabase => "Hash not found in signature database",
            UefiError::HashRevoked => "Hash found in revocation database",
            UefiError::AllocationFailed { .. } => "Memory allocation failed",
            UefiError::NullPointer { .. } => "Null pointer encountered",
            UefiError::Timeout { .. } => "Operation timed out",
            UefiError::UnsupportedRevision { .. } => "Table revision not supported",
            UefiError::ProtocolNotFound { .. } => "Protocol not found",
            UefiError::VariableNameTooLong { .. } => "Variable name too long",
            UefiError::VariableDataTooLarge { .. } => "Variable data too large",
        }
    }

    pub fn from_efi_status(efi_status: u64) -> Option<Self> {
        match efi_status {
            status::EFI_SUCCESS => None,
            status::EFI_NOT_FOUND => Some(UefiError::VariableNotFound { name: "unknown" }),
            status::EFI_ACCESS_DENIED => Some(UefiError::AccessDenied),
            status::EFI_WRITE_PROTECTED => Some(UefiError::WriteProtected),
            status::EFI_SECURITY_VIOLATION => Some(UefiError::SecurityViolation),
            status::EFI_OUT_OF_RESOURCES => Some(UefiError::OutOfResources),
            status::EFI_INVALID_PARAMETER => Some(UefiError::InvalidParameter { param: "unknown" }),
            status::EFI_BUFFER_TOO_SMALL => Some(UefiError::BufferTooSmall {
                required: 0,
                provided: 0,
            }),
            status::EFI_TIMEOUT => Some(UefiError::Timeout { operation: "unknown" }),
            status::EFI_UNSUPPORTED => Some(UefiError::RuntimeServicesNotAvailable),
            status::EFI_DEVICE_ERROR => Some(UefiError::VariableReadFailed { status: efi_status }),
            _ => Some(UefiError::VariableReadFailed { status: efi_status }),
        }
    }

    pub const fn to_efi_status(&self) -> u64 {
        match self {
            UefiError::NotInitialized => status::EFI_NOT_STARTED,
            UefiError::AlreadyInitialized => status::EFI_ALREADY_STARTED,
            UefiError::RuntimeServicesNotAvailable => status::EFI_UNSUPPORTED,
            UefiError::BootServicesExited => status::EFI_UNSUPPORTED,
            UefiError::VariableNotFound { .. } => status::EFI_NOT_FOUND,
            UefiError::VariableWriteFailed { status } => *status,
            UefiError::VariableReadFailed { status } => *status,
            UefiError::InvalidSignature { .. } => status::EFI_COMPROMISED_DATA,
            UefiError::CrcMismatch { .. } => status::EFI_CRC_ERROR,
            UefiError::SecureBootFailed => status::EFI_SECURITY_VIOLATION,
            UefiError::NotInSetupMode => status::EFI_ACCESS_DENIED,
            UefiError::InvalidGuid => status::EFI_INVALID_PARAMETER,
            UefiError::BufferTooSmall { .. } => status::EFI_BUFFER_TOO_SMALL,
            UefiError::AccessDenied => status::EFI_ACCESS_DENIED,
            UefiError::WriteProtected => status::EFI_WRITE_PROTECTED,
            UefiError::SecurityViolation => status::EFI_SECURITY_VIOLATION,
            UefiError::OutOfResources => status::EFI_OUT_OF_RESOURCES,
            UefiError::InvalidParameter { .. } => status::EFI_INVALID_PARAMETER,
            UefiError::SignatureListParseError { .. } => status::EFI_COMPROMISED_DATA,
            UefiError::HashNotInDatabase => status::EFI_NOT_FOUND,
            UefiError::HashRevoked => status::EFI_SECURITY_VIOLATION,
            UefiError::AllocationFailed { .. } => status::EFI_OUT_OF_RESOURCES,
            UefiError::NullPointer { .. } => status::EFI_INVALID_PARAMETER,
            UefiError::Timeout { .. } => status::EFI_TIMEOUT,
            UefiError::UnsupportedRevision { .. } => status::EFI_INCOMPATIBLE_VERSION,
            UefiError::ProtocolNotFound { .. } => status::EFI_NOT_FOUND,
            UefiError::VariableNameTooLong { .. } => status::EFI_INVALID_PARAMETER,
            UefiError::VariableDataTooLarge { .. } => status::EFI_BAD_BUFFER_SIZE,
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            UefiError::NotInitialized
                | UefiError::BufferTooSmall { .. }
                | UefiError::Timeout { .. }
                | UefiError::OutOfResources
        )
    }
  
    pub const fn is_security_error(&self) -> bool {
        matches!(
            self,
            UefiError::SecureBootFailed
                | UefiError::NotInSetupMode
                | UefiError::AccessDenied
                | UefiError::WriteProtected
                | UefiError::SecurityViolation
                | UefiError::HashRevoked
        )
    }
}

impl fmt::Display for UefiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UefiError::VariableNotFound { name } => {
                write!(f, "UEFI variable not found: {}", name)
            }
            UefiError::VariableWriteFailed { status } => {
                write!(
                    f,
                    "UEFI variable write failed: {} (0x{:x})",
                    status::name(*status),
                    status
                )
            }
            UefiError::VariableReadFailed { status } => {
                write!(
                    f,
                    "UEFI variable read failed: {} (0x{:x})",
                    status::name(*status),
                    status
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

/// Result type for UEFI operations
pub type UefiResult<T> = Result<T, UefiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(UefiError::NotInitialized.as_str(), "UEFI not initialized");
        assert_eq!(UefiError::HashRevoked.as_str(), "Hash found in revocation database");
        assert_eq!(
            UefiError::HashNotInDatabase.as_str(),
            "Hash not found in signature database"
        );
    }

    #[test]
    fn test_from_efi_status() {
        assert!(UefiError::from_efi_status(status::EFI_SUCCESS).is_none());
        assert!(matches!(
            UefiError::from_efi_status(status::EFI_NOT_FOUND),
            Some(UefiError::VariableNotFound { .. })
        ));
        assert!(matches!(
            UefiError::from_efi_status(status::EFI_ACCESS_DENIED),
            Some(UefiError::AccessDenied)
        ));
    }

    #[test]
    fn test_to_efi_status() {
        assert_eq!(UefiError::NotInitialized.to_efi_status(), status::EFI_NOT_STARTED);
        assert_eq!(UefiError::AccessDenied.to_efi_status(), status::EFI_ACCESS_DENIED);
        assert_eq!(UefiError::HashRevoked.to_efi_status(), status::EFI_SECURITY_VIOLATION);
    }

    #[test]
    fn test_is_recoverable() {
        assert!(UefiError::NotInitialized.is_recoverable());
        assert!(UefiError::OutOfResources.is_recoverable());
        assert!(!UefiError::AccessDenied.is_recoverable());
        assert!(!UefiError::HashRevoked.is_recoverable());
    }

    #[test]
    fn test_is_security_error() {
        assert!(UefiError::SecureBootFailed.is_security_error());
        assert!(UefiError::AccessDenied.is_security_error());
        assert!(UefiError::HashRevoked.is_security_error());
        assert!(!UefiError::NotInitialized.is_security_error());
        assert!(!UefiError::OutOfResources.is_security_error());
    }

    #[test]
    fn test_display() {
        let err = UefiError::BufferTooSmall {
            required: 1024,
            provided: 512,
        };
        let s = format!("{}", err);
        assert!(s.contains("1024"));
        assert!(s.contains("512"));

        let err = UefiError::InvalidSignature {
            expected: 0x1234,
            found: 0x5678,
        };
        let s = format!("{}", err);
        assert!(s.contains("1234"));
        assert!(s.contains("5678"));
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(UefiError::NotInitialized, UefiError::NotInitialized);
        assert_ne!(UefiError::NotInitialized, UefiError::AlreadyInitialized);

        assert_eq!(
            UefiError::VariableNotFound { name: "test" },
            UefiError::VariableNotFound { name: "test" }
        );
        assert_ne!(
            UefiError::VariableNotFound { name: "test1" },
            UefiError::VariableNotFound { name: "test2" }
        );
    }

    #[test]
    fn test_error_clone() {
        let err = UefiError::BufferTooSmall {
            required: 100,
            provided: 50,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}
