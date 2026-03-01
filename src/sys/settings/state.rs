// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use core::sync::atomic::{AtomicBool, Ordering};
use super::types::Settings;

pub(super) static mut CURRENT_SETTINGS: Settings = Settings::default();
pub(super) static SETTINGS_LOADED: AtomicBool = AtomicBool::new(false);
pub(super) static SETTINGS_MODIFIED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    unsafe {
        CURRENT_SETTINGS = Settings::default();
    }
    SETTINGS_LOADED.store(true, Ordering::SeqCst);
}

pub fn get() -> Settings {
    unsafe { CURRENT_SETTINGS }
}

pub fn get_mut() -> &'static mut Settings {
    unsafe { &mut *(&raw mut CURRENT_SETTINGS) }
}

pub fn mark_modified() {
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
}

pub fn needs_save() -> bool {
    SETTINGS_MODIFIED.load(Ordering::Relaxed)
}

pub(super) fn clear_modified() {
    SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
}

pub fn reset_to_defaults() {
    unsafe {
        CURRENT_SETTINGS = Settings::default();
    }
    mark_modified();
}
