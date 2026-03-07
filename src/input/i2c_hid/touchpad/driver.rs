// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Touchpad driver for I2C HID precision touchpads.
//!
//! This driver handles:
//! - HID report parsing for various touchpad formats
//! - Absolute to relative coordinate conversion
//! - Movement smoothing and noise filtering
//! - Jump detection and filtering

use super::types::{TouchpadState, Gesture};
use super::parsing;
use super::constants::{TAP_TIMEOUT_US, DOUBLE_TAP_TIMEOUT_US};
use crate::input::i2c_hid::descriptor::TouchpadLayout;

/// Get current timestamp in microseconds
fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}

/// Touchpad driver that processes HID reports and calculates cursor movement.
pub struct TouchpadDriver {
    // Touchpad specifications from HID descriptor
    logical_max_x: i32,
    logical_max_y: i32,
    layout: TouchpadLayout,

    // Tracking state for delta calculation
    last_x: i32,
    last_y: i32,
    is_tracking: bool,

    // Smoothing state
    accumulated_dx: i32,
    accumulated_dy: i32,

    // Tap detection state
    tap_start_time: u64,
    tap_start_x: i32,
    tap_start_y: i32,
    tap_enabled: bool,
    last_tap_time: u64,
    tap_count: u8,
    was_touching: bool,
    sensitivity: i32,
    acceleration: i32,
    palm_rejection: bool,
}

impl TouchpadDriver {
    /// Create a new touchpad driver.
    pub fn new(
        logical_max_x: i32,
        logical_max_y: i32,
        _max_contacts: u8,
        layout: TouchpadLayout,
    ) -> Self {
        Self {
            // Ensure reasonable minimums for logical max
            logical_max_x: logical_max_x.max(1000),
            logical_max_y: logical_max_y.max(1000),
            layout,
            last_x: 0,
            last_y: 0,
            is_tracking: false,
            accumulated_dx: 0,
            accumulated_dy: 0,
            tap_start_time: 0,
            tap_start_x: 0,
            tap_start_y: 0,
            tap_enabled: true,
            last_tap_time: 0,
            tap_count: 0,
            was_touching: false,
            sensitivity: 100,
            acceleration: 100,
            palm_rejection: true,
        }
    }

    /// Check if using parsed HID layout (vs fallback heuristics).
    pub fn is_using_layout(&self) -> bool {
        self.layout.contacts[0].x.is_valid() && self.layout.contacts[0].y.is_valid()
    }

    /// Get logical maximum X coordinate.
    pub fn logical_max_x(&self) -> i32 {
        self.logical_max_x
    }

    /// Get logical maximum Y coordinate.
    pub fn logical_max_y(&self) -> i32 {
        self.logical_max_y
    }

    /// Process a HID input report and return touchpad state.
    ///
    /// This is the main entry point for processing touchpad data.
    pub fn process_report(&mut self, _report_id: u8, data: &[u8]) -> Option<TouchpadState> {
        let mut state = TouchpadState::default();

        // Need at least 4 bytes for any valid report
        if data.len() < 4 {
            self.reset_tracking();
            return Some(state);
        }

        // Extract touch coordinates using best available method
        let touch = self.extract_touch(data);
        let now = timestamp();

        match touch {
            Some((x, y)) => {
                // Valid touch detected
                state.contact_count = 1;
                state.contacts[0].x = x;
                state.contacts[0].y = y;
                state.contacts[0].tip = true;

                // Start tap tracking if this is a new touch
                if !self.was_touching && self.tap_enabled {
                    self.tap_start_time = now;
                    self.tap_start_x = x;
                    self.tap_start_y = y;
                }
                self.was_touching = true;

                // Calculate delta movement
                let (dx, dy) = self.calculate_delta(x, y);
                state.delta_x = dx;
                state.delta_y = dy;
            }
            None => {
                // Finger lifted - check for tap gesture
                if self.was_touching && self.tap_enabled {
                    state.gesture = self.detect_tap(now);
                }
                self.was_touching = false;

                // No touch - reset tracking
                self.reset_tracking();
            }
        }

        Some(state)
    }

    /// Detect tap gestures based on timing and movement
    fn detect_tap(&mut self, now: u64) -> Gesture {
        let tap_duration = now.saturating_sub(self.tap_start_time);

        // Check if tap was quick enough
        if tap_duration > TAP_TIMEOUT_US {
            self.tap_count = 0;
            return Gesture::None;
        }

        // Check if finger moved too much (would be a drag, not a tap)
        let dx = (self.last_x - self.tap_start_x).abs();
        let dy = (self.last_y - self.tap_start_y).abs();
        let max_tap_movement = self.logical_max_x / 50; // ~2% of touchpad width
        if dx > max_tap_movement || dy > max_tap_movement {
            self.tap_count = 0;
            return Gesture::None;
        }

        // Check for double tap
        let time_since_last_tap = now.saturating_sub(self.last_tap_time);
        if time_since_last_tap < DOUBLE_TAP_TIMEOUT_US && self.tap_count > 0 {
            self.tap_count = 0;
            self.last_tap_time = 0;
            return Gesture::DoubleTap;
        }

        // Single tap
        self.tap_count = 1;
        self.last_tap_time = now;
        Gesture::Tap
    }

    /// Extract touch coordinates from HID report data.
    fn extract_touch(&self, data: &[u8]) -> Option<(i32, i32)> {
        // Try parsed HID layout first (most accurate)
        if self.is_using_layout() {
            if let Some(coords) = self.extract_from_layout(data) {
                return Some(coords);
            }
        }

        // Fallback: try common touchpad formats
        self.extract_fallback(data)
    }

    /// Extract coordinates using parsed HID descriptor layout.
    fn extract_from_layout(&self, data: &[u8]) -> Option<(i32, i32)> {
        let contact = &self.layout.contacts[0];

        // Check tip switch (finger touching) if available
        if contact.tip_switch.is_valid() {
            let tip = contact.tip_switch.extract(data);
            if tip == 0 {
                return None; // Finger not touching
            }
        }

        // Extract X and Y coordinates
        let x = contact.x.extract(data);
        let y = contact.y.extract(data);

        // Validate coordinates
        if self.is_valid_coordinate(x, y) {
            Some((x, y))
        } else {
            None
        }
    }

    /// Fallback extraction for when HID layout parsing isn't available.
    fn extract_fallback(&self, data: &[u8]) -> Option<(i32, i32)> {
        let mut state = TouchpadState::default();

        if parsing::try_parse_hp_precision_touchpad(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_precision_touchpad(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_windows_precision(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_synaptics(data, &mut state) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_elan(data, &mut state) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_standard_touchpad(data, &mut state, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        // Try Format D: Raw coordinates (last resort)
        if let Some(coords) = self.try_format_raw(data) {
            return Some(coords);
        }

        None
    }

    /// Raw coordinates (last resort).
    fn try_format_raw(&self, data: &[u8]) -> Option<(i32, i32)> {
        if data.len() < 4 {
            return None;
        }

        let x = u16::from_le_bytes([data[0], data[1]]) as i32;
        let y = u16::from_le_bytes([data[2], data[3]]) as i32;

        // Must look like real coordinates (not zero or tiny values)
        if x > 100 && y > 100 && self.is_valid_coordinate(x, y) {
            Some((x, y))
        } else {
            None
        }
    }

    /// Check if coordinates are within valid bounds.
    fn is_valid_coordinate(&self, x: i32, y: i32) -> bool {
        x > 0 && y > 0 && x <= self.logical_max_x && y <= self.logical_max_y
    }

    /// Calculate delta movement from current position.
    fn calculate_delta(&mut self, x: i32, y: i32) -> (i32, i32) {
        if !self.is_tracking {
            // First touch - start tracking, no movement yet
            self.last_x = x;
            self.last_y = y;
            self.is_tracking = true;
            self.accumulated_dx = 0;
            self.accumulated_dy = 0;
            return (0, 0);
        }

        // Calculate raw delta
        let raw_dx = x - self.last_x;
        let raw_dy = y - self.last_y;

        // Update last position
        self.last_x = x;
        self.last_y = y;

        // Filter out huge jumps (likely finger lift/place or parsing error)
        let max_jump = self.logical_max_x / 4;
        if raw_dx.abs() > max_jump || raw_dy.abs() > max_jump {
            // Suspicious jump - ignore this frame
            return (0, 0);
        }

        // Scale: convert touchpad units to screen pixels
        // Higher resolution touchpads need more scaling
        let scale = self.calculate_scale();

        let scaled_dx = raw_dx / scale;
        let scaled_dy = raw_dy / scale;

        // Accumulate sub-pixel movement
        self.accumulated_dx += raw_dx % scale;
        self.accumulated_dy += raw_dy % scale;

        // Convert accumulated to pixels when threshold reached
        let extra_dx = self.accumulated_dx / scale;
        let extra_dy = self.accumulated_dy / scale;
        self.accumulated_dx %= scale;
        self.accumulated_dy %= scale;

        let final_dx = scaled_dx + extra_dx;
        let final_dy = scaled_dy + extra_dy;

        // Clamp to reasonable per-frame movement
        (final_dx.clamp(-20, 20), final_dy.clamp(-20, 20))
    }

    /// Calculate scaling factor based on touchpad resolution.
    fn calculate_scale(&self) -> i32 {
        // Target: moving 1cm on touchpad = ~40 pixels on screen
        // Typical touchpad: ~10cm wide, 4000 units = 400 units/cm
        // So we want 400 touchpad units = 40 pixels = scale of 10
        //
        // Formula: scale = logical_max / (physical_size_cm * pixels_per_cm)
        // Simplified: scale = logical_max / 400
        (self.logical_max_x / 400).max(1)
    }

    /// Reset tracking state (called when finger lifts).
    fn reset_tracking(&mut self) {
        self.is_tracking = false;
        self.accumulated_dx = 0;
        self.accumulated_dy = 0;
    }

    /// Set pointer sensitivity (1-200, default 100).
    /// Higher values increase cursor movement per touchpad distance.
    pub fn set_sensitivity(&mut self, sensitivity: i32) {
        self.sensitivity = sensitivity.clamp(1, 200);
    }

    /// Set pointer acceleration curve (1-200, default 100).
    /// Higher values increase acceleration for fast movements.
    pub fn set_acceleration(&mut self, acceleration: i32) {
        self.acceleration = acceleration.clamp(1, 200);
    }

    /// Enable or disable palm rejection filtering.
    /// When enabled, large contact areas are ignored as accidental touches.
    pub fn set_palm_rejection(&mut self, enabled: bool) {
        self.palm_rejection = enabled;
    }

    /// Get current sensitivity setting.
    pub fn sensitivity(&self) -> i32 {
        self.sensitivity
    }

    /// Get current acceleration setting.
    pub fn acceleration(&self) -> i32 {
        self.acceleration
    }

    /// Check if palm rejection is enabled.
    pub fn palm_rejection_enabled(&self) -> bool {
        self.palm_rejection
    }

    /// Enable or disable tap-to-click gesture detection
    pub fn set_tap_to_click(&mut self, enabled: bool) {
        self.tap_enabled = enabled;
        if !enabled {
            self.tap_count = 0;
            self.last_tap_time = 0;
        }
    }

    /// Check if tap-to-click is enabled
    pub fn is_tap_enabled(&self) -> bool {
        self.tap_enabled
    }

    /// Parse buttons from a raw report data
    pub fn parse_buttons(&self, data: &[u8], offset: usize) -> u8 {
        parsing::parse_buttons(data, offset)
    }

    /// Parse a contact point from raw report data
    pub fn parse_contact_point(&self, data: &[u8], offset: usize) -> Option<super::TouchPoint> {
        parsing::parse_contact_point(data, offset)
    }
}
