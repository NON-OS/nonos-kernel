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

use crate::drivers::nvme::error;
use crate::test::framework::TestResult;

pub(crate) fn test_error_display() -> TestResult {
    let err = error::NvmeError::NoControllerFound;
    if err.as_str() != "No NVMe controller found on PCI bus" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_classification() -> TestResult {
    if !error::NvmeError::ControllerFatalStatus.is_fatal() {
        return TestResult::Fail;
    }
    if !error::NvmeError::CqCorruption.is_fatal() {
        return TestResult::Fail;
    }
    if error::NvmeError::CommandTimeout.is_fatal() {
        return TestResult::Fail;
    }

    if !error::NvmeError::CommandTimeout.is_recoverable() {
        return TestResult::Fail;
    }
    if !error::NvmeError::RateLimitExceeded.is_recoverable() {
        return TestResult::Fail;
    }
    if error::NvmeError::ControllerFatalStatus.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_code_parsing() -> TestResult {
    let status = error::NvmeStatusCode::from_status_field(0x0000);
    if !status.is_success() {
        return TestResult::Fail;
    }

    let status = error::NvmeStatusCode::from_status_field(0x0002);
    if status != error::NvmeStatusCode::InvalidOpcode {
        return TestResult::Fail;
    }

    let status = error::NvmeStatusCode::from_status_field(0x0004);
    if status != error::NvmeStatusCode::InvalidField {
        return TestResult::Fail;
    }
    TestResult::Pass
}
