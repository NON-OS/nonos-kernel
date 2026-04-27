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

use crate::drivers::xhci::{constants, types};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_usb_device_descriptor_size() -> TestResult {
    if mem::size_of::<types::UsbDeviceDescriptor>() != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_device_descriptor_validation() -> TestResult {
    let mut desc = types::UsbDeviceDescriptor::default();
    if desc.validate() {
        return TestResult::Fail;
    }

    desc.length = 18;
    desc.descriptor_type = constants::DESC_TYPE_DEVICE;
    if !desc.validate() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_usb_version_parsing() -> TestResult {
    let mut desc = types::UsbDeviceDescriptor::default();
    desc.bcd_usb = 0x0200;

    let (major, minor) = desc.usb_version();
    if major != 2 {
        return TestResult::Fail;
    }
    if minor != 0 {
        return TestResult::Fail;
    }

    desc.bcd_usb = 0x0310;
    let (major, minor) = desc.usb_version();
    if major != 3 {
        return TestResult::Fail;
    }
    if minor != 0x10 {
        return TestResult::Fail;
    }

    TestResult::Pass
}
