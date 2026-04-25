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

use crate::drivers::pci::*;
use crate::test::framework::TestResult;

pub(crate) fn test_error_display() -> TestResult {
    use core::fmt::Write;
    let err = error::PciError::InvalidDevice(32);
    let mut buf = [0u8; 128];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    let msg = writer.as_str();
    if !msg.contains("32") {
        return TestResult::Fail;
    }

    let err = error::PciError::DeviceBlocked { vendor: 0x1234, device: 0x5678 };
    let mut buf2 = [0u8; 128];
    let mut writer2 = crate::test::framework::ArrayWriter::new(&mut buf2);
    let _ = write!(writer2, "{}", err);
    let msg2 = writer2.as_str();
    if !msg2.contains("1234") {
        return TestResult::Fail;
    }
    if !msg2.contains("5678") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_classification() -> TestResult {
    if !error::PciError::RootComplexError.is_fatal() {
        return TestResult::Fail;
    }
    if error::PciError::DeviceNotFound.is_fatal() {
        return TestResult::Fail;
    }

    if !(error::PciError::DeviceBlocked { vendor: 0, device: 0 }).is_security_related() {
        return TestResult::Fail;
    }
    if error::PciError::DeviceNotFound.is_security_related() {
        return TestResult::Fail;
    }

    if !error::PciError::DeviceNotFound.is_recoverable() {
        return TestResult::Fail;
    }
    if error::PciError::RootComplexError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_ordering() -> TestResult {
    if !(security::SecurityLevel::Critical > security::SecurityLevel::High) {
        return TestResult::Fail;
    }
    if !(security::SecurityLevel::High > security::SecurityLevel::Medium) {
        return TestResult::Fail;
    }
    if !(security::SecurityLevel::Medium > security::SecurityLevel::Low) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
