// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Display settings state - connects to real GPU driver and framebuffer.

use crate::drivers::gpu::driver::GpuDriver;
use crate::graphics::framebuffer;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

static RESOLUTION_IDX: AtomicU8 = AtomicU8::new(0);
static REFRESH_RATE: AtomicU8 = AtomicU8::new(60);
static SCALE_FACTOR: AtomicU8 = AtomicU8::new(100);
static NIGHT_SHIFT: AtomicBool = AtomicBool::new(false);
static BRIGHTNESS: AtomicU8 = AtomicU8::new(100);
static COLOR_TEMP: AtomicU16 = AtomicU16::new(6500);

#[derive(Clone, Copy)]
pub struct DisplayState {
    pub resolution_idx: u8,
    pub refresh_rate: u8,
    pub scale_factor: u8,
    pub night_shift_enabled: bool,
    pub brightness: u8,
    pub color_temperature: u16,
    pub actual_width: u32,
    pub actual_height: u32,
}

impl DisplayState {
    pub fn resolution_str(&self) -> &'static str {
        super::resolution::RESOLUTIONS
            .get(self.resolution_idx as usize)
            .map(|r| r.0)
            .unwrap_or("1920x1080")
    }
}

/// Get current display state from real framebuffer
pub(super) fn get_state() -> DisplayState {
    let (actual_width, actual_height) = framebuffer::dimensions();

    DisplayState {
        resolution_idx: RESOLUTION_IDX.load(Ordering::Relaxed),
        refresh_rate: REFRESH_RATE.load(Ordering::Relaxed),
        scale_factor: SCALE_FACTOR.load(Ordering::Relaxed),
        night_shift_enabled: NIGHT_SHIFT.load(Ordering::Relaxed),
        brightness: BRIGHTNESS.load(Ordering::Relaxed),
        color_temperature: COLOR_TEMP.load(Ordering::Relaxed),
        actual_width,
        actual_height,
    }
}

/// Set resolution - delegates to real GPU driver
pub(super) fn set_resolution(idx: u8) {
    if let Some(&(_, width, height)) = super::resolution::RESOLUTIONS.get(idx as usize) {
        // Try to set the mode via GPU driver
        if GpuDriver::set_mode_32bpp(width as u16, height as u16).is_ok() {
            RESOLUTION_IDX.store(idx, Ordering::Relaxed);
            // Update input subsystem screen bounds
            crate::input::set_screen_bounds_unified(width, height);
        }
    }
}

/// Set UI scale factor (100 = 100%)
pub(super) fn set_scale(scale: u8) {
    SCALE_FACTOR.store(scale.clamp(50, 200), Ordering::Relaxed);
}

/// Enable/disable night shift (warm color temperature)
pub(super) fn set_night_shift(enabled: bool) {
    NIGHT_SHIFT.store(enabled, Ordering::Relaxed);
    if enabled {
        COLOR_TEMP.store(4500, Ordering::Relaxed); // Warmer
    } else {
        COLOR_TEMP.store(6500, Ordering::Relaxed); // Standard
    }
}

/// Set brightness (0-100)
pub(super) fn set_brightness(val: u8) {
    BRIGHTNESS.store(val.min(100), Ordering::Relaxed);
}

/// Get current brightness
pub(super) fn get_brightness() -> u8 {
    BRIGHTNESS.load(Ordering::Relaxed)
}

/// Get current scale factor
pub(super) fn get_scale_factor() -> u8 {
    SCALE_FACTOR.load(Ordering::Relaxed)
}

/// Check if night shift is enabled
pub(super) fn is_night_shift_enabled() -> bool {
    NIGHT_SHIFT.load(Ordering::Relaxed)
}

/// Get color temperature in Kelvin
pub(super) fn get_color_temperature() -> u16 {
    COLOR_TEMP.load(Ordering::Relaxed)
}
