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

//! Accessibility settings state - real settings that affect graphics rendering.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// Global accessibility settings used by the graphics subsystem
static FONT_SIZE: AtomicU8 = AtomicU8::new(1);
static CURSOR_SIZE: AtomicU8 = AtomicU8::new(1);
static BOLD_TEXT: AtomicBool = AtomicBool::new(false);
static HIGH_CONTRAST: AtomicBool = AtomicBool::new(false);
static REDUCE_MOTION: AtomicBool = AtomicBool::new(false);
static REDUCE_TRANSPARENCY: AtomicBool = AtomicBool::new(false);
static INVERT_COLORS: AtomicBool = AtomicBool::new(false);
static KEYBOARD_NAV: AtomicBool = AtomicBool::new(false);
static ZOOM_ENABLED: AtomicBool = AtomicBool::new(false);
static ZOOM_LEVEL: AtomicU8 = AtomicU8::new(100);

pub(super) static FONT_SIZES: &[(&str, u8)] =
    &[("Small", 0), ("Default", 1), ("Large", 2), ("Extra Large", 3)];
pub(super) static CURSOR_SIZES: &[(&str, u8)] = &[("Normal", 1), ("Large", 2), ("Extra Large", 3)];

#[derive(Clone, Copy)]
pub struct AccessibilityState {
    pub font_size_idx: u8,
    pub cursor_size_idx: u8,
    pub bold_text: bool,
    pub high_contrast: bool,
    pub reduce_motion: bool,
    pub reduce_transparency: bool,
    pub invert_colors: bool,
    pub keyboard_navigation: bool,
    pub zoom_enabled: bool,
    pub zoom_level: u8,
}

pub(super) fn get_state() -> AccessibilityState {
    AccessibilityState {
        font_size_idx: FONT_SIZE.load(Ordering::Relaxed),
        cursor_size_idx: CURSOR_SIZE.load(Ordering::Relaxed),
        bold_text: BOLD_TEXT.load(Ordering::Relaxed),
        high_contrast: HIGH_CONTRAST.load(Ordering::Relaxed),
        reduce_motion: REDUCE_MOTION.load(Ordering::Relaxed),
        reduce_transparency: REDUCE_TRANSPARENCY.load(Ordering::Relaxed),
        invert_colors: INVERT_COLORS.load(Ordering::Relaxed),
        keyboard_navigation: KEYBOARD_NAV.load(Ordering::Relaxed),
        zoom_enabled: ZOOM_ENABLED.load(Ordering::Relaxed),
        zoom_level: ZOOM_LEVEL.load(Ordering::Relaxed),
    }
}

pub(super) fn set_font_size(idx: u8) {
    FONT_SIZE.store(idx.min(3), Ordering::Relaxed);
}
pub(super) fn set_cursor_size(idx: u8) {
    CURSOR_SIZE.store(idx.min(3), Ordering::Relaxed);
}
pub(super) fn set_bold_text(v: bool) {
    BOLD_TEXT.store(v, Ordering::Relaxed);
}
pub(super) fn set_high_contrast(v: bool) {
    HIGH_CONTRAST.store(v, Ordering::Relaxed);
}
pub(super) fn set_reduce_motion(v: bool) {
    REDUCE_MOTION.store(v, Ordering::Relaxed);
}
pub(super) fn set_reduce_transparency(v: bool) {
    REDUCE_TRANSPARENCY.store(v, Ordering::Relaxed);
}
pub(super) fn set_invert_colors(v: bool) {
    INVERT_COLORS.store(v, Ordering::Relaxed);
}
pub(super) fn set_keyboard_nav(v: bool) {
    KEYBOARD_NAV.store(v, Ordering::Relaxed);
}
pub(super) fn set_zoom_enabled(v: bool) {
    ZOOM_ENABLED.store(v, Ordering::Relaxed);
}

// ============ Public API for Graphics Subsystem ============

/// Get font size multiplier (1.0 = normal, 0.8 = small, 1.2 = large, 1.5 = extra large)
pub(super) fn font_scale() -> u8 {
    match FONT_SIZE.load(Ordering::Relaxed) {
        0 => 80,  // Small = 0.8x
        1 => 100, // Default = 1.0x
        2 => 120, // Large = 1.2x
        3 => 150, // Extra Large = 1.5x
        _ => 100,
    }
}

/// Get cursor size multiplier (1 = normal, 2 = large, 3 = extra large)
pub(super) fn cursor_scale() -> u8 {
    CURSOR_SIZE.load(Ordering::Relaxed).max(1)
}

/// Check if high contrast mode is enabled
pub(super) fn is_high_contrast() -> bool {
    HIGH_CONTRAST.load(Ordering::Relaxed)
}

/// Check if motion should be reduced (for animations)
pub(super) fn should_reduce_motion() -> bool {
    REDUCE_MOTION.load(Ordering::Relaxed)
}

/// Check if transparency should be reduced
pub(super) fn should_reduce_transparency() -> bool {
    REDUCE_TRANSPARENCY.load(Ordering::Relaxed)
}

/// Check if colors should be inverted
pub(super) fn should_invert_colors() -> bool {
    INVERT_COLORS.load(Ordering::Relaxed)
}

/// Check if keyboard navigation is enabled
pub(super) fn is_keyboard_nav_enabled() -> bool {
    KEYBOARD_NAV.load(Ordering::Relaxed)
}

/// Check if zoom is enabled
pub(super) fn is_zoom_enabled() -> bool {
    ZOOM_ENABLED.load(Ordering::Relaxed)
}

/// Get zoom level (100 = 100%)
pub(super) fn zoom_level() -> u8 {
    ZOOM_LEVEL.load(Ordering::Relaxed)
}
