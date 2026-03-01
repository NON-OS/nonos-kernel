// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::state::{CURRENT_SETTINGS, mark_modified};

pub fn brightness() -> u8 {
    unsafe { CURRENT_SETTINGS.brightness }
}

pub fn set_brightness(val: u8) {
    unsafe {
        CURRENT_SETTINGS.brightness = val.min(100);
    }
    mark_modified();
}

pub fn mouse_sensitivity() -> u8 {
    unsafe { CURRENT_SETTINGS.mouse_sensitivity }
}

pub fn set_mouse_sensitivity(val: u8) {
    unsafe {
        CURRENT_SETTINGS.mouse_sensitivity = val.clamp(1, 10);
    }
    mark_modified();
}

pub fn anonymous_mode() -> bool {
    unsafe { CURRENT_SETTINGS.anonymous_mode }
}

pub fn set_anonymous_mode(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.anonymous_mode = enabled;
    }
    mark_modified();
}

pub fn anyone_enabled() -> bool {
    unsafe { CURRENT_SETTINGS.anyone_enabled }
}

pub fn set_anyone_enabled(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.anyone_enabled = enabled;
    }
    mark_modified();
}

pub fn theme() -> u8 {
    unsafe { CURRENT_SETTINGS.theme }
}

pub fn set_theme(t: u8) {
    unsafe {
        CURRENT_SETTINGS.theme = t;
    }
    mark_modified();
}

pub fn auto_wipe() -> bool {
    unsafe { CURRENT_SETTINGS.auto_wipe }
}

pub fn set_auto_wipe(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.auto_wipe = enabled;
    }
    mark_modified();
}
