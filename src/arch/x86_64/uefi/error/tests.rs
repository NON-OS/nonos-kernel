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

#[cfg(test)]
mod tests {
    use super::super::types::UefiError;
    use crate::arch::x86_64::uefi::constants::status;

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
