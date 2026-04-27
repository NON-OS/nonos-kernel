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

use crate::drivers::xhci::XhciError;
use crate::test::framework::TestResult;

pub(crate) fn test_error_display() -> TestResult {
    let err = XhciError::InvalidSlotId(5);
    if err.as_str() != "Invalid slot ID" {
        return TestResult::Fail;
    }

    let err = XhciError::Timeout;
    if err.as_str() != "Operation timeout" {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_completion_code_extraction() -> TestResult {
    let err = XhciError::CompletionCodeError(6);
    if err.completion_code() != Some(6) {
        return TestResult::Fail;
    }

    let err = XhciError::Timeout;
    if err.completion_code() != None {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_error_requires_reset() -> TestResult {
    if !XhciError::Stall.requires_endpoint_reset() {
        return TestResult::Fail;
    }
    if !XhciError::BabbleDetected.requires_endpoint_reset() {
        return TestResult::Fail;
    }
    if XhciError::Timeout.requires_endpoint_reset() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable() -> TestResult {
    if !XhciError::Timeout.is_recoverable() {
        return TestResult::Fail;
    }
    if !XhciError::Stall.is_recoverable() {
        return TestResult::Fail;
    }
    if !XhciError::HostSystemError.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_from_completion_code() -> TestResult {
    if XhciError::from_completion_code(1).is_some() {
        return TestResult::Fail;
    }
    if !matches!(XhciError::from_completion_code(6), Some(XhciError::Stall)) {
        return TestResult::Fail;
    }
    if !matches!(XhciError::from_completion_code(3), Some(XhciError::BabbleDetected)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
