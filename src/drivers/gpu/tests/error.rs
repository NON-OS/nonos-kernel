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

use crate::drivers::gpu::error::GpuError;
use crate::test::framework::TestResult;

pub(crate) fn test_error_device_not_found_str() -> TestResult {
    if GpuError::DeviceNotFound.as_str() != "GPU device not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_initialization_failed_str() -> TestResult {
    if GpuError::InitializationFailed.as_str() != "GPU initialization failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_bar_str() -> TestResult {
    if GpuError::InvalidBar.as_str() != "Invalid BAR configuration" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_unsupported_mode_str() -> TestResult {
    if GpuError::UnsupportedMode.as_str() != "Unsupported display mode" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_resolution_str() -> TestResult {
    if GpuError::InvalidResolution.as_str() != "Invalid resolution" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_color_depth_str() -> TestResult {
    if GpuError::InvalidColorDepth.as_str() != "Invalid color depth" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_framebuffer_allocation_failed_str() -> TestResult {
    if GpuError::FramebufferAllocationFailed.as_str() != "Framebuffer allocation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_mode_set_failed_str() -> TestResult {
    if GpuError::ModeSetFailed.as_str() != "Mode set failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_vsync_timeout_str() -> TestResult {
    if GpuError::VsyncTimeout.as_str() != "VSync timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_coordinates_str() -> TestResult {
    if GpuError::InvalidCoordinates.as_str() != "Invalid coordinates" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_out_of_bounds_str() -> TestResult {
    if GpuError::OutOfBounds.as_str() != "Drawing out of bounds" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small_str() -> TestResult {
    if GpuError::BufferTooSmall.as_str() != "Buffer too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_pixel_format_str() -> TestResult {
    if GpuError::InvalidPixelFormat.as_str() != "Invalid pixel format" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_blit_failed_str() -> TestResult {
    if GpuError::BlitFailed.as_str() != "Blit operation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_cursor_error_str() -> TestResult {
    if GpuError::CursorError.as_str() != "Hardware cursor error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_vsync_timeout_recoverable() -> TestResult {
    if !GpuError::VsyncTimeout.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_out_of_bounds_recoverable() -> TestResult {
    if !GpuError::OutOfBounds.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_coordinates_recoverable() -> TestResult {
    if !GpuError::InvalidCoordinates.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_device_not_found_not_recoverable() -> TestResult {
    if GpuError::DeviceNotFound.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_initialization_failed_not_recoverable() -> TestResult {
    if GpuError::InitializationFailed.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_bar_not_recoverable() -> TestResult {
    if GpuError::InvalidBar.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_unsupported_mode_not_recoverable() -> TestResult {
    if GpuError::UnsupportedMode.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_resolution_not_recoverable() -> TestResult {
    if GpuError::InvalidResolution.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_color_depth_not_recoverable() -> TestResult {
    if GpuError::InvalidColorDepth.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_framebuffer_allocation_failed_not_recoverable() -> TestResult {
    if GpuError::FramebufferAllocationFailed.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_mode_set_failed_not_recoverable() -> TestResult {
    if GpuError::ModeSetFailed.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small_not_recoverable() -> TestResult {
    if GpuError::BufferTooSmall.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_pixel_format_not_recoverable() -> TestResult {
    if GpuError::InvalidPixelFormat.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_blit_failed_not_recoverable() -> TestResult {
    if GpuError::BlitFailed.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_cursor_error_not_recoverable() -> TestResult {
    if GpuError::CursorError.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if GpuError::VsyncTimeout != GpuError::VsyncTimeout {
        return TestResult::Fail;
    }
    if GpuError::VsyncTimeout == GpuError::OutOfBounds {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err1 = GpuError::ModeSetFailed;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err1 = GpuError::BlitFailed;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug() -> TestResult {
    use core::fmt::Write;
    let err = GpuError::InvalidResolution;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", err);
    let debug_str = writer.as_str();
    if debug_str != "InvalidResolution" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display() -> TestResult {
    use core::fmt::Write;
    let err = GpuError::InvalidResolution;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    let display_str = writer.as_str();
    if display_str != "Invalid resolution" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_errors_have_message() -> TestResult {
    let errors = [
        GpuError::DeviceNotFound,
        GpuError::InitializationFailed,
        GpuError::InvalidBar,
        GpuError::UnsupportedMode,
        GpuError::InvalidResolution,
        GpuError::InvalidColorDepth,
        GpuError::FramebufferAllocationFailed,
        GpuError::ModeSetFailed,
        GpuError::VsyncTimeout,
        GpuError::InvalidCoordinates,
        GpuError::OutOfBounds,
        GpuError::BufferTooSmall,
        GpuError::InvalidPixelFormat,
        GpuError::BlitFailed,
        GpuError::CursorError,
    ];

    for err in &errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
