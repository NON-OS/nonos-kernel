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
use crate::test::framework::TestResult;

pub(crate) fn test_error_not_initialized_str() -> TestResult {
    if TpmError::NotInitialized.as_str() != "TPM not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_present_str() -> TestResult {
    if TpmError::NotPresent.as_str() != "TPM not present" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_timeout_str() -> TestResult {
    if TpmError::Timeout.as_str() != "TPM operation timed out" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_response_str() -> TestResult {
    if TpmError::InvalidResponse.as_str() != "invalid TPM response" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_locality_error_str() -> TestResult {
    if TpmError::LocalityError.as_str() != "locality access error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed_str() -> TestResult {
    if TpmError::CommandFailed(0x123).as_str() != "TPM command failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small_str() -> TestResult {
    if TpmError::BufferTooSmall.as_str() != "buffer too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_parameter_str() -> TestResult {
    if TpmError::InvalidParameter.as_str() != "invalid parameter" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_auth_failed_str() -> TestResult {
    if TpmError::AuthFailed.as_str() != "authentication failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_nv_error_str() -> TestResult {
    if TpmError::NvError.as_str() != "NV storage error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_pcr_error_str() -> TestResult {
    if TpmError::PcrError.as_str() != "PCR operation error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_communication_error_str() -> TestResult {
    if TpmError::CommunicationError.as_str() != "communication error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_hardware_error_str() -> TestResult {
    if TpmError::HardwareError.as_str() != "hardware error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_rate_limit_exceeded_str() -> TestResult {
    if TpmError::RateLimitExceeded.as_str() != "rate limit exceeded" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed_response_code() -> TestResult {
    let err = TpmError::CommandFailed(0x123);
    if err.response_code() != Some(0x123) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_timeout_response_code_none() -> TestResult {
    if TpmError::Timeout.response_code() != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_present_response_code_none() -> TestResult {
    if TpmError::NotPresent.response_code() != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_timeout_recoverable() -> TestResult {
    if !TpmError::Timeout.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_locality_error_recoverable() -> TestResult {
    if !TpmError::LocalityError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small_recoverable() -> TestResult {
    if !TpmError::BufferTooSmall.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_parameter_recoverable() -> TestResult {
    if !TpmError::InvalidParameter.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_rate_limit_exceeded_recoverable() -> TestResult {
    if !TpmError::RateLimitExceeded.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_present_not_recoverable() -> TestResult {
    if TpmError::NotPresent.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_hardware_error_not_recoverable() -> TestResult {
    if TpmError::HardwareError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed_not_recoverable() -> TestResult {
    if TpmError::CommandFailed(0).is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_present_fatal() -> TestResult {
    if !TpmError::NotPresent.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_hardware_error_fatal() -> TestResult {
    if !TpmError::HardwareError.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_timeout_not_fatal() -> TestResult {
    if TpmError::Timeout.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed_not_fatal() -> TestResult {
    if TpmError::CommandFailed(0x100).is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if TpmError::Timeout != TpmError::Timeout {
        return TestResult::Fail;
    }
    if TpmError::Timeout == TpmError::NotPresent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed_equality() -> TestResult {
    if TpmError::CommandFailed(0x100) != TpmError::CommandFailed(0x100) {
        return TestResult::Fail;
    }
    if TpmError::CommandFailed(0x100) == TpmError::CommandFailed(0x200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err1 = TpmError::PcrError;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err1 = TpmError::NvError;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug() -> TestResult {
    use core::fmt::Write;
    let err = TpmError::Timeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", err);
    if writer.as_str() != "Timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display_timeout() -> TestResult {
    use core::fmt::Write;
    let err = TpmError::Timeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    if writer.as_str() != "TPM operation timed out" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display_command_failed() -> TestResult {
    use core::fmt::Write;
    let err = TpmError::CommandFailed(0x123);
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    if writer.as_str() != "TPM command failed with code 0x00000123" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_errors_have_message() -> TestResult {
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
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
