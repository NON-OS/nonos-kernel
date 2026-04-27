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

use crate::display::*;
use crate::test::framework::TestResult;

pub(crate) fn test_display_error_not_initialized_display() -> TestResult {
    let err = DisplayError::NotInitialized;
    let msg = alloc::format!("{}", err);
    if !msg.contains("not initialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_invalid_address_display() -> TestResult {
    let err = DisplayError::InvalidAddress;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid") {
        return TestResult::Fail;
    }
    if !msg.contains("address") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_out_of_bounds_display() -> TestResult {
    let err = DisplayError::OutOfBounds;
    let msg = alloc::format!("{}", err);
    if !msg.contains("out of bounds") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_invalid_format_display() -> TestResult {
    let err = DisplayError::InvalidFormat;
    let msg = alloc::format!("{}", err);
    if !msg.contains("invalid") {
        return TestResult::Fail;
    }
    if !msg.contains("format") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_no_framebuffer_display() -> TestResult {
    let err = DisplayError::NoFramebuffer;
    let msg = alloc::format!("{}", err);
    if !msg.contains("no framebuffer") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_equality() -> TestResult {
    if DisplayError::NotInitialized != DisplayError::NotInitialized {
        return TestResult::Fail;
    }
    if DisplayError::InvalidAddress != DisplayError::InvalidAddress {
        return TestResult::Fail;
    }
    if DisplayError::OutOfBounds != DisplayError::OutOfBounds {
        return TestResult::Fail;
    }
    if DisplayError::InvalidFormat != DisplayError::InvalidFormat {
        return TestResult::Fail;
    }
    if DisplayError::NoFramebuffer != DisplayError::NoFramebuffer {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_inequality() -> TestResult {
    if DisplayError::NotInitialized == DisplayError::InvalidAddress {
        return TestResult::Fail;
    }
    if DisplayError::InvalidAddress == DisplayError::OutOfBounds {
        return TestResult::Fail;
    }
    if DisplayError::OutOfBounds == DisplayError::InvalidFormat {
        return TestResult::Fail;
    }
    if DisplayError::InvalidFormat == DisplayError::NoFramebuffer {
        return TestResult::Fail;
    }
    if DisplayError::NoFramebuffer == DisplayError::NotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_debug() -> TestResult {
    let err = DisplayError::NotInitialized;
    let debug = alloc::format!("{:?}", err);
    if !debug.contains("NotInitialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_clone() -> TestResult {
    let err = DisplayError::OutOfBounds;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_copy() -> TestResult {
    let err = DisplayError::InvalidFormat;
    let copied = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_variants_distinct() -> TestResult {
    let errors = [
        DisplayError::NotInitialized,
        DisplayError::InvalidAddress,
        DisplayError::OutOfBounds,
        DisplayError::InvalidFormat,
        DisplayError::NoFramebuffer,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            if errors[i] == errors[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_display_error_debug_all_variants() -> TestResult {
    let debug = alloc::format!("{:?}", DisplayError::InvalidAddress);
    if !debug.contains("InvalidAddress") {
        return TestResult::Fail;
    }

    let debug = alloc::format!("{:?}", DisplayError::OutOfBounds);
    if !debug.contains("OutOfBounds") {
        return TestResult::Fail;
    }

    let debug = alloc::format!("{:?}", DisplayError::InvalidFormat);
    if !debug.contains("InvalidFormat") {
        return TestResult::Fail;
    }

    let debug = alloc::format!("{:?}", DisplayError::NoFramebuffer);
    if !debug.contains("NoFramebuffer") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
