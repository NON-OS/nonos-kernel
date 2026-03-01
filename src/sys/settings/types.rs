// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Settings types and structures

/// System settings (runtime copy in RAM)
#[derive(Clone, Copy)]
pub struct Settings {
    /// Display brightness (0-100)
    pub brightness: u8,
    pub mouse_sensitivity: u8,
    pub sound_enabled: bool,
    pub anonymous_mode: bool,
    pub anyone_enabled: bool,
    pub theme: u8,
    pub keyboard_layout: u8,
    pub auto_wipe: bool,
}

impl Settings {
    pub const fn default() -> Self {
        Self {
            brightness: 80,
            mouse_sensitivity: 5,
            sound_enabled: true,
            anonymous_mode: true,
            anyone_enabled: false,
            theme: 0,
            keyboard_layout: 0,
            auto_wipe: true,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::default()
    }
}
