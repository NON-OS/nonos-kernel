// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Global state for I2C HID touchpad subsystem.
//!
//! This module manages all shared state for the touchpad driver including
//! cursor position, screen bounds, and device list.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use spin::Mutex;

use super::device::I2cHidDevice;

// =============================================================================
// GLOBAL STATE
// =============================================================================

/// List of detected I2C HID devices
pub static DEVICES: Mutex<Vec<I2cHidDevice>> = Mutex::new(Vec::new());

/// Whether a touchpad is available and initialized
pub static TOUCHPAD_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Current cursor X position (screen coordinates)
pub static CURSOR_X: AtomicI32 = AtomicI32::new(400);

/// Current cursor Y position (screen coordinates)
pub static CURSOR_Y: AtomicI32 = AtomicI32::new(300);

/// Screen width in pixels
pub static SCREEN_W: AtomicI32 = AtomicI32::new(800);

/// Screen height in pixels
pub static SCREEN_H: AtomicI32 = AtomicI32::new(600);

/// Count of successful touchpad updates (for diagnostics)
pub static UPDATE_COUNT: AtomicU32 = AtomicU32::new(0);

// =============================================================================
// PUBLIC API
// =============================================================================

/// Check if touchpad is available
#[inline]
pub fn is_available() -> bool {
    TOUCHPAD_AVAILABLE.load(Ordering::Acquire)
}

/// Set touchpad availability
#[inline]
pub fn set_available(available: bool) {
    TOUCHPAD_AVAILABLE.store(available, Ordering::Release);
}

/// Get current cursor position
#[inline]
pub fn get_cursor() -> (i32, i32) {
    (
        CURSOR_X.load(Ordering::Acquire),
        CURSOR_Y.load(Ordering::Acquire),
    )
}

/// Set cursor position (clamped to screen bounds)
pub fn set_cursor(x: i32, y: i32) {
    let w = SCREEN_W.load(Ordering::Acquire);
    let h = SCREEN_H.load(Ordering::Acquire);

    let clamped_x = x.clamp(0, w.saturating_sub(1));
    let clamped_y = y.clamp(0, h.saturating_sub(1));

    CURSOR_X.store(clamped_x, Ordering::Release);
    CURSOR_Y.store(clamped_y, Ordering::Release);
}

/// Move cursor by delta (clamped to screen bounds)
pub fn move_cursor(dx: i32, dy: i32) {
    let x = CURSOR_X.load(Ordering::Acquire);
    let y = CURSOR_Y.load(Ordering::Acquire);
    set_cursor(x.saturating_add(dx), y.saturating_add(dy));
}

/// Set screen dimensions and center cursor
pub fn set_screen_size(width: u32, height: u32) {
    let w = width as i32;
    let h = height as i32;

    SCREEN_W.store(w, Ordering::Release);
    SCREEN_H.store(h, Ordering::Release);

    // Center cursor on screen
    CURSOR_X.store(w / 2, Ordering::Release);
    CURSOR_Y.store(h / 2, Ordering::Release);
}

/// Get screen dimensions
#[inline]
pub fn get_screen_size() -> (i32, i32) {
    (
        SCREEN_W.load(Ordering::Acquire),
        SCREEN_H.load(Ordering::Acquire),
    )
}

/// Increment update counter (for diagnostics)
pub fn record_update() {
    let _ = UPDATE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get update count
#[inline]
pub fn get_update_count() -> u32 {
    UPDATE_COUNT.load(Ordering::Relaxed)
}

/// Get number of registered devices
pub fn device_count() -> usize {
    DEVICES.lock().len()
}

/// Add a device to the list
pub fn add_device(device: I2cHidDevice) {
    DEVICES.lock().push(device);
}
