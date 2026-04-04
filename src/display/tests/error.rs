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

#[test]
fn test_display_error_not_initialized_display() {
    let err = DisplayError::NotInitialized;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("not initialized"));
}

#[test]
fn test_display_error_invalid_address_display() {
    let err = DisplayError::InvalidAddress;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid"));
    assert!(msg.contains("address"));
}

#[test]
fn test_display_error_out_of_bounds_display() {
    let err = DisplayError::OutOfBounds;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("out of bounds"));
}

#[test]
fn test_display_error_invalid_format_display() {
    let err = DisplayError::InvalidFormat;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("invalid"));
    assert!(msg.contains("format"));
}

#[test]
fn test_display_error_no_framebuffer_display() {
    let err = DisplayError::NoFramebuffer;
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("no framebuffer"));
}

#[test]
fn test_display_error_equality() {
    assert_eq!(DisplayError::NotInitialized, DisplayError::NotInitialized);
    assert_eq!(DisplayError::InvalidAddress, DisplayError::InvalidAddress);
    assert_eq!(DisplayError::OutOfBounds, DisplayError::OutOfBounds);
    assert_eq!(DisplayError::InvalidFormat, DisplayError::InvalidFormat);
    assert_eq!(DisplayError::NoFramebuffer, DisplayError::NoFramebuffer);
}

#[test]
fn test_display_error_inequality() {
    assert_ne!(DisplayError::NotInitialized, DisplayError::InvalidAddress);
    assert_ne!(DisplayError::InvalidAddress, DisplayError::OutOfBounds);
    assert_ne!(DisplayError::OutOfBounds, DisplayError::InvalidFormat);
    assert_ne!(DisplayError::InvalidFormat, DisplayError::NoFramebuffer);
    assert_ne!(DisplayError::NoFramebuffer, DisplayError::NotInitialized);
}

#[test]
fn test_display_error_debug() {
    let err = DisplayError::NotInitialized;
    let debug = alloc::format!("{:?}", err);
    assert!(debug.contains("NotInitialized"));
}

#[test]
fn test_display_error_clone() {
    let err = DisplayError::OutOfBounds;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_display_error_copy() {
    let err = DisplayError::InvalidFormat;
    let copied = err;
    assert_eq!(err, copied);
}

#[test]
fn test_all_error_variants_distinct() {
    let errors = [
        DisplayError::NotInitialized,
        DisplayError::InvalidAddress,
        DisplayError::OutOfBounds,
        DisplayError::InvalidFormat,
        DisplayError::NoFramebuffer,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            assert_ne!(errors[i], errors[j]);
        }
    }
}

#[test]
fn test_display_error_debug_all_variants() {
    let debug = alloc::format!("{:?}", DisplayError::InvalidAddress);
    assert!(debug.contains("InvalidAddress"));

    let debug = alloc::format!("{:?}", DisplayError::OutOfBounds);
    assert!(debug.contains("OutOfBounds"));

    let debug = alloc::format!("{:?}", DisplayError::InvalidFormat);
    assert!(debug.contains("InvalidFormat"));

    let debug = alloc::format!("{:?}", DisplayError::NoFramebuffer);
    assert!(debug.contains("NoFramebuffer"));
}
