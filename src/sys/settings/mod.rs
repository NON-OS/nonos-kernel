// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Settings persistence module for NONOS
//!
//! Provides save/load functionality for system settings.
//! Settings are stored in a simple key=value format on FAT32.

// Submodules
pub mod network;
mod types;
mod state;
mod api;
mod serialize;
mod persistence;
mod hostname;

pub use types::Settings;

pub use state::{init, get, get_mut, mark_modified, needs_save, reset_to_defaults};

pub use api::{
    brightness, set_brightness,
    mouse_sensitivity, set_mouse_sensitivity,
    anonymous_mode, set_anonymous_mode,
    anyone_enabled, set_anyone_enabled,
    theme, set_theme,
    auto_wipe, set_auto_wipe,
};

pub use persistence::{save_to_disk, load_from_disk, SETTINGS_FILENAME};

pub use serialize::{serialize, deserialize};

pub use hostname::{
    init as init_hostname,
    get as get_hostname,
    set as set_hostname,
    get_domain as get_domainname,
    set_domain as set_domainname,
};
