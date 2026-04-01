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
    pub brightness: u8,
    pub mouse_sensitivity: u8,
    pub sound_enabled: bool,
    pub anonymous_mode: bool,
    pub nym_enabled: bool,
    pub theme: u8,
    pub keyboard_layout: u8,
    pub auto_wipe: bool,
    pub timezone: i8,
    pub screen_timeout: u8,
    pub language: u8,
    pub developer_mode: bool,
    pub hardware_crypto: bool,
    pub zk_attestation: bool,
    pub system_keys_generated: bool,
}

impl Settings {
    pub const fn default() -> Self {
        Self {
            brightness: 80,
            mouse_sensitivity: 5,
            sound_enabled: true,
            anonymous_mode: true,
            nym_enabled: false,
            theme: 0,
            keyboard_layout: 0,
            auto_wipe: true,
            timezone: 0,
            screen_timeout: 0,
            language: 0,
            developer_mode: false,
            hardware_crypto: true,
            zk_attestation: true,
            system_keys_generated: false,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::default()
    }
}
