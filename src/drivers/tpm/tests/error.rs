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

use crate::drivers::tpm::error::TpmError;

#[test]
fn test_error_not_initialized_str() {
    assert_eq!(TpmError::NotInitialized.as_str(), "TPM not initialized");
}

#[test]
fn test_error_not_present_str() {
    assert_eq!(TpmError::NotPresent.as_str(), "TPM not present");
}

#[test]
fn test_error_timeout_str() {
    assert_eq!(TpmError::Timeout.as_str(), "TPM operation timed out");
}

#[test]
fn test_error_invalid_response_str() {
    assert_eq!(TpmError::InvalidResponse.as_str(), "invalid TPM response");
}

#[test]
fn test_error_locality_error_str() {
    assert_eq!(TpmError::LocalityError.as_str(), "locality access error");
}

#[test]
fn test_error_command_failed_str() {
    assert_eq!(TpmError::CommandFailed(0x123).as_str(), "TPM command failed");
}

#[test]
fn test_error_buffer_too_small_str() {
    assert_eq!(TpmError::BufferTooSmall.as_str(), "buffer too small");
}

#[test]
fn test_error_invalid_parameter_str() {
    assert_eq!(TpmError::InvalidParameter.as_str(), "invalid parameter");
}

#[test]
fn test_error_auth_failed_str() {
    assert_eq!(TpmError::AuthFailed.as_str(), "authentication failed");
}

#[test]
fn test_error_nv_error_str() {
    assert_eq!(TpmError::NvError.as_str(), "NV storage error");
}

#[test]
fn test_error_pcr_error_str() {
    assert_eq!(TpmError::PcrError.as_str(), "PCR operation error");
}

#[test]
fn test_error_communication_error_str() {
    assert_eq!(TpmError::CommunicationError.as_str(), "communication error");
}

#[test]
fn test_error_hardware_error_str() {
    assert_eq!(TpmError::HardwareError.as_str(), "hardware error");
}

#[test]
fn test_error_rate_limit_exceeded_str() {
    assert_eq!(TpmError::RateLimitExceeded.as_str(), "rate limit exceeded");
}

#[test]
fn test_error_command_failed_response_code() {
    let err = TpmError::CommandFailed(0x123);
    assert_eq!(err.response_code(), Some(0x123));
}

#[test]
fn test_error_timeout_response_code_none() {
    assert_eq!(TpmError::Timeout.response_code(), None);
}

#[test]
fn test_error_not_present_response_code_none() {
    assert_eq!(TpmError::NotPresent.response_code(), None);
}

#[test]
fn test_error_timeout_recoverable() {
    assert!(TpmError::Timeout.is_recoverable());
}

#[test]
fn test_error_locality_error_recoverable() {
    assert!(TpmError::LocalityError.is_recoverable());
}

#[test]
fn test_error_buffer_too_small_recoverable() {
    assert!(TpmError::BufferTooSmall.is_recoverable());
}

#[test]
fn test_error_invalid_parameter_recoverable() {
    assert!(TpmError::InvalidParameter.is_recoverable());
}

#[test]
fn test_error_rate_limit_exceeded_recoverable() {
    assert!(TpmError::RateLimitExceeded.is_recoverable());
}

#[test]
fn test_error_not_present_not_recoverable() {
    assert!(!TpmError::NotPresent.is_recoverable());
}

#[test]
fn test_error_hardware_error_not_recoverable() {
    assert!(!TpmError::HardwareError.is_recoverable());
}

#[test]
fn test_error_command_failed_not_recoverable() {
    assert!(!TpmError::CommandFailed(0).is_recoverable());
}

#[test]
fn test_error_not_present_fatal() {
    assert!(TpmError::NotPresent.is_fatal());
}

#[test]
fn test_error_hardware_error_fatal() {
    assert!(TpmError::HardwareError.is_fatal());
}

#[test]
fn test_error_timeout_not_fatal() {
    assert!(!TpmError::Timeout.is_fatal());
}

#[test]
fn test_error_command_failed_not_fatal() {
    assert!(!TpmError::CommandFailed(0x100).is_fatal());
}

#[test]
fn test_error_equality() {
    assert_eq!(TpmError::Timeout, TpmError::Timeout);
    assert_ne!(TpmError::Timeout, TpmError::NotPresent);
}

#[test]
fn test_error_command_failed_equality() {
    assert_eq!(TpmError::CommandFailed(0x100), TpmError::CommandFailed(0x100));
    assert_ne!(TpmError::CommandFailed(0x100), TpmError::CommandFailed(0x200));
}

#[test]
fn test_error_copy() {
    let err1 = TpmError::PcrError;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = TpmError::NvError;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = TpmError::Timeout;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "Timeout");
}

#[test]
fn test_error_display_timeout() {
    let err = TpmError::Timeout;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "TPM operation timed out");
}

#[test]
fn test_error_display_command_failed() {
    let err = TpmError::CommandFailed(0x123);
    let display_str = format!("{}", err);
    assert_eq!(display_str, "TPM command failed with code 0x00000123");
}

#[test]
fn test_all_errors_have_message() {
    let errors = [
        TpmError::NotInitialized,
        TpmError::NotPresent,
        TpmError::Timeout,
        TpmError::InvalidResponse,
        TpmError::LocalityError,
        TpmError::CommandFailed(0),
        TpmError::BufferTooSmall,
        TpmError::InvalidParameter,
        TpmError::AuthFailed,
        TpmError::NvError,
        TpmError::PcrError,
        TpmError::CommunicationError,
        TpmError::HardwareError,
        TpmError::RateLimitExceeded,
    ];

    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}
