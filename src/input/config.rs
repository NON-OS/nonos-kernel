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

//! Input subsystem configuration - real settings that affect input behavior.
//!
//! These settings are used by the input drivers to modify cursor movement,
//! scroll behavior, keyboard repeat rates, and other input parameters.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// Mouse settings
static TRACKING_SPEED: AtomicU8 = AtomicU8::new(50);
static SCROLL_SPEED: AtomicU8 = AtomicU8::new(50);
static DOUBLE_CLICK_SPEED: AtomicU8 = AtomicU8::new(50);
static NATURAL_SCROLL: AtomicBool = AtomicBool::new(true);
static SECONDARY_CLICK: AtomicBool = AtomicBool::new(true);
static POINTER_ACCELERATION: AtomicBool = AtomicBool::new(true);

// Keyboard settings
static KEY_REPEAT_RATE: AtomicU8 = AtomicU8::new(30);
static KEY_REPEAT_DELAY: AtomicU8 = AtomicU8::new(50);
static LAYOUT_INDEX: AtomicU8 = AtomicU8::new(0);

/// Available keyboard layouts
pub static LAYOUTS: &[&str] = &["US", "UK", "DE", "FR", "ES", "IT", "JP", "KR"];

/// Mouse configuration state
#[derive(Clone, Copy)]
pub struct MouseConfig {
    pub tracking_speed: u8,
    pub scroll_speed: u8,
    pub double_click_speed: u8,
    pub natural_scroll: bool,
    pub secondary_click: bool,
    pub pointer_acceleration: bool,
}

/// Keyboard configuration state
#[derive(Clone, Copy)]
pub struct KeyboardConfig {
    pub repeat_rate: u8,
    pub repeat_delay: u8,
    pub layout_index: u8,
}

impl KeyboardConfig {
    pub fn layout_name(&self) -> &'static str {
        LAYOUTS.get(self.layout_index as usize).copied().unwrap_or("US")
    }
}

// ============ Mouse Configuration API ============

/// Get current mouse configuration
pub fn get_mouse_config() -> MouseConfig {
    MouseConfig {
        tracking_speed: TRACKING_SPEED.load(Ordering::Relaxed),
        scroll_speed: SCROLL_SPEED.load(Ordering::Relaxed),
        double_click_speed: DOUBLE_CLICK_SPEED.load(Ordering::Relaxed),
        natural_scroll: NATURAL_SCROLL.load(Ordering::Relaxed),
        secondary_click: SECONDARY_CLICK.load(Ordering::Relaxed),
        pointer_acceleration: POINTER_ACCELERATION.load(Ordering::Relaxed),
    }
}

/// Set mouse tracking speed (0-100, affects cursor movement multiplier)
pub fn set_tracking_speed(speed: u8) {
    TRACKING_SPEED.store(speed.min(100), Ordering::Relaxed);
}

/// Set scroll wheel speed (0-100, affects scroll delta multiplier)
pub fn set_scroll_speed(speed: u8) {
    SCROLL_SPEED.store(speed.min(100), Ordering::Relaxed);
}

/// Set double-click speed threshold (0-100, lower = faster required)
pub fn set_double_click_speed(speed: u8) {
    DOUBLE_CLICK_SPEED.store(speed.min(100), Ordering::Relaxed);
}

/// Enable/disable natural (reversed) scrolling
pub fn set_natural_scroll(enabled: bool) {
    NATURAL_SCROLL.store(enabled, Ordering::Relaxed);
}

/// Enable/disable secondary (right) click
pub fn set_secondary_click(enabled: bool) {
    SECONDARY_CLICK.store(enabled, Ordering::Relaxed);
}

/// Enable/disable pointer acceleration
pub fn set_pointer_acceleration(enabled: bool) {
    POINTER_ACCELERATION.store(enabled, Ordering::Relaxed);
}

/// Get tracking speed multiplier (1.0 at 50, 0.5-2.0 range)
pub fn tracking_multiplier() -> i32 {
    let speed = TRACKING_SPEED.load(Ordering::Relaxed) as i32;
    // Scale: 0 = 0.5x, 50 = 1.0x, 100 = 2.0x
    // Return as fixed-point *100 for integer math
    50 + speed
}

/// Get scroll speed multiplier
pub fn scroll_multiplier() -> i32 {
    let speed = SCROLL_SPEED.load(Ordering::Relaxed) as i32;
    50 + speed
}

/// Check if natural scroll is enabled
pub fn is_natural_scroll() -> bool {
    NATURAL_SCROLL.load(Ordering::Relaxed)
}

/// Check if pointer acceleration is enabled
pub fn has_pointer_acceleration() -> bool {
    POINTER_ACCELERATION.load(Ordering::Relaxed)
}

/// Get double-click threshold in milliseconds
pub fn double_click_threshold_ms() -> u32 {
    let speed = DOUBLE_CLICK_SPEED.load(Ordering::Relaxed) as u32;
    // 0 = 800ms (slow), 50 = 400ms (normal), 100 = 200ms (fast)
    800 - (speed * 6)
}

// ============ Keyboard Configuration API ============

/// Get current keyboard configuration
pub fn get_keyboard_config() -> KeyboardConfig {
    KeyboardConfig {
        repeat_rate: KEY_REPEAT_RATE.load(Ordering::Relaxed),
        repeat_delay: KEY_REPEAT_DELAY.load(Ordering::Relaxed),
        layout_index: LAYOUT_INDEX.load(Ordering::Relaxed),
    }
}

/// Set key repeat rate (0-100, higher = faster repeat)
pub fn set_repeat_rate(rate: u8) {
    KEY_REPEAT_RATE.store(rate.min(100), Ordering::Relaxed);
}

/// Set key repeat delay (0-100, higher = longer delay before repeat starts)
pub fn set_repeat_delay(delay: u8) {
    KEY_REPEAT_DELAY.store(delay.min(100), Ordering::Relaxed);
}

/// Set keyboard layout by index
pub fn set_layout(idx: u8) {
    if (idx as usize) < LAYOUTS.len() {
        LAYOUT_INDEX.store(idx, Ordering::Relaxed);
    }
}

/// Get repeat rate in characters per second
pub fn repeat_rate_cps() -> u32 {
    let rate = KEY_REPEAT_RATE.load(Ordering::Relaxed) as u32;
    // 0 = 2 cps, 50 = 15 cps, 100 = 30 cps
    2 + (rate * 28 / 100)
}

/// Get repeat delay in milliseconds
pub fn repeat_delay_ms() -> u32 {
    let delay = KEY_REPEAT_DELAY.load(Ordering::Relaxed) as u32;
    // 0 = 200ms, 50 = 400ms, 100 = 1000ms
    200 + (delay * 8)
}

/// Get current layout name
pub fn current_layout() -> &'static str {
    LAYOUTS.get(LAYOUT_INDEX.load(Ordering::Relaxed) as usize).copied().unwrap_or("US")
}

// ============ Reset to Defaults ============

/// Reset all input settings to defaults
pub fn reset_defaults() {
    // Mouse defaults
    TRACKING_SPEED.store(50, Ordering::Relaxed);
    SCROLL_SPEED.store(50, Ordering::Relaxed);
    DOUBLE_CLICK_SPEED.store(50, Ordering::Relaxed);
    NATURAL_SCROLL.store(true, Ordering::Relaxed);
    SECONDARY_CLICK.store(true, Ordering::Relaxed);
    POINTER_ACCELERATION.store(true, Ordering::Relaxed);
    // Keyboard defaults
    KEY_REPEAT_RATE.store(30, Ordering::Relaxed);
    KEY_REPEAT_DELAY.store(50, Ordering::Relaxed);
    LAYOUT_INDEX.store(0, Ordering::Relaxed);
}
