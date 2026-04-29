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

//! Keyboard settings state - delegates to the real input subsystem config.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::input::config;

// These settings are keyboard-specific but not part of the input config
static CAPS_LOCK_LED: AtomicBool = AtomicBool::new(true);
static FN_KEY_STANDARD: AtomicBool = AtomicBool::new(false);

/// Re-export layouts from input config
pub(super) static LAYOUTS: &[&str] = config::LAYOUTS;

/// Keyboard settings state
#[derive(Clone, Copy)]
pub struct KeyboardState {
    pub repeat_rate: u8,
    pub repeat_delay: u8,
    pub caps_lock_led: bool,
    pub fn_key_standard: bool,
    pub layout_index: u8,
}

impl KeyboardState {
    pub fn layout_name(&self) -> &'static str {
        LAYOUTS.get(self.layout_index as usize).copied().unwrap_or("US")
    }
}

/// Get current state from the real input subsystem
pub(super) fn get_state() -> KeyboardState {
    let cfg = config::get_keyboard_config();
    KeyboardState {
        repeat_rate: cfg.repeat_rate,
        repeat_delay: cfg.repeat_delay,
        caps_lock_led: CAPS_LOCK_LED.load(Ordering::Relaxed),
        fn_key_standard: FN_KEY_STANDARD.load(Ordering::Relaxed),
        layout_index: cfg.layout_index,
    }
}

/// Set repeat rate - delegates to real input subsystem
pub(super) fn set_repeat_rate(rate: u8) {
    config::set_repeat_rate(rate);
}

/// Set repeat delay - delegates to real input subsystem
pub(super) fn set_repeat_delay(delay: u8) {
    config::set_repeat_delay(delay);
}

/// Set caps lock LED indicator (local setting)
pub(super) fn set_caps_lock_led(enabled: bool) {
    CAPS_LOCK_LED.store(enabled, Ordering::Relaxed);
}

/// Set function key behavior (local setting)
pub(super) fn set_fn_key_standard(standard: bool) {
    FN_KEY_STANDARD.store(standard, Ordering::Relaxed);
}

/// Set keyboard layout - delegates to real input subsystem
pub(super) fn set_layout(idx: u8) {
    config::set_layout(idx);
}
