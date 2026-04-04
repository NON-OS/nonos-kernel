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

#[test]
fn test_error_device_not_found_str() {
    assert_eq!(GpuError::DeviceNotFound.as_str(), "GPU device not found");
}

#[test]
fn test_error_initialization_failed_str() {
    assert_eq!(GpuError::InitializationFailed.as_str(), "GPU initialization failed");
}

#[test]
fn test_error_invalid_bar_str() {
    assert_eq!(GpuError::InvalidBar.as_str(), "Invalid BAR configuration");
}

#[test]
fn test_error_unsupported_mode_str() {
    assert_eq!(GpuError::UnsupportedMode.as_str(), "Unsupported display mode");
}

#[test]
fn test_error_invalid_resolution_str() {
    assert_eq!(GpuError::InvalidResolution.as_str(), "Invalid resolution");
}

#[test]
fn test_error_invalid_color_depth_str() {
    assert_eq!(GpuError::InvalidColorDepth.as_str(), "Invalid color depth");
}

#[test]
fn test_error_framebuffer_allocation_failed_str() {
    assert_eq!(GpuError::FramebufferAllocationFailed.as_str(), "Framebuffer allocation failed");
}

#[test]
fn test_error_mode_set_failed_str() {
    assert_eq!(GpuError::ModeSetFailed.as_str(), "Mode set failed");
}

#[test]
fn test_error_vsync_timeout_str() {
    assert_eq!(GpuError::VsyncTimeout.as_str(), "VSync timeout");
}

#[test]
fn test_error_invalid_coordinates_str() {
    assert_eq!(GpuError::InvalidCoordinates.as_str(), "Invalid coordinates");
}

#[test]
fn test_error_out_of_bounds_str() {
    assert_eq!(GpuError::OutOfBounds.as_str(), "Drawing out of bounds");
}

#[test]
fn test_error_buffer_too_small_str() {
    assert_eq!(GpuError::BufferTooSmall.as_str(), "Buffer too small");
}

#[test]
fn test_error_invalid_pixel_format_str() {
    assert_eq!(GpuError::InvalidPixelFormat.as_str(), "Invalid pixel format");
}

#[test]
fn test_error_blit_failed_str() {
    assert_eq!(GpuError::BlitFailed.as_str(), "Blit operation failed");
}

#[test]
fn test_error_cursor_error_str() {
    assert_eq!(GpuError::CursorError.as_str(), "Hardware cursor error");
}

#[test]
fn test_error_vsync_timeout_recoverable() {
    assert!(GpuError::VsyncTimeout.is_recoverable());
}

#[test]
fn test_error_out_of_bounds_recoverable() {
    assert!(GpuError::OutOfBounds.is_recoverable());
}

#[test]
fn test_error_invalid_coordinates_recoverable() {
    assert!(GpuError::InvalidCoordinates.is_recoverable());
}

#[test]
fn test_error_device_not_found_not_recoverable() {
    assert!(!GpuError::DeviceNotFound.is_recoverable());
}

#[test]
fn test_error_initialization_failed_not_recoverable() {
    assert!(!GpuError::InitializationFailed.is_recoverable());
}

#[test]
fn test_error_invalid_bar_not_recoverable() {
    assert!(!GpuError::InvalidBar.is_recoverable());
}

#[test]
fn test_error_unsupported_mode_not_recoverable() {
    assert!(!GpuError::UnsupportedMode.is_recoverable());
}

#[test]
fn test_error_invalid_resolution_not_recoverable() {
    assert!(!GpuError::InvalidResolution.is_recoverable());
}

#[test]
fn test_error_invalid_color_depth_not_recoverable() {
    assert!(!GpuError::InvalidColorDepth.is_recoverable());
}

#[test]
fn test_error_framebuffer_allocation_failed_not_recoverable() {
    assert!(!GpuError::FramebufferAllocationFailed.is_recoverable());
}

#[test]
fn test_error_mode_set_failed_not_recoverable() {
    assert!(!GpuError::ModeSetFailed.is_recoverable());
}

#[test]
fn test_error_buffer_too_small_not_recoverable() {
    assert!(!GpuError::BufferTooSmall.is_recoverable());
}

#[test]
fn test_error_invalid_pixel_format_not_recoverable() {
    assert!(!GpuError::InvalidPixelFormat.is_recoverable());
}

#[test]
fn test_error_blit_failed_not_recoverable() {
    assert!(!GpuError::BlitFailed.is_recoverable());
}

#[test]
fn test_error_cursor_error_not_recoverable() {
    assert!(!GpuError::CursorError.is_recoverable());
}

#[test]
fn test_error_equality() {
    assert_eq!(GpuError::VsyncTimeout, GpuError::VsyncTimeout);
    assert_ne!(GpuError::VsyncTimeout, GpuError::OutOfBounds);
}

#[test]
fn test_error_copy() {
    let err1 = GpuError::ModeSetFailed;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = GpuError::BlitFailed;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = GpuError::InvalidResolution;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "InvalidResolution");
}

#[test]
fn test_error_display() {
    let err = GpuError::InvalidResolution;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "Invalid resolution");
}

#[test]
fn test_all_errors_have_message() {
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
        assert!(!err.as_str().is_empty());
    }
}
