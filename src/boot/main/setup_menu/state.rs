// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, Ordering};

static SETUP_COMPLETE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct SetupConfig {
    pub language_index: usize,
    pub wallpaper_index: Option<usize>,
    pub generate_keys: bool,
    pub hardware_crypto: bool,
    pub zk_attestation: bool,
    pub developer_mode: bool,
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            language_index: 0,
            wallpaper_index: Some(0),
            generate_keys: true,
            hardware_crypto: true,
            zk_attestation: true,
            developer_mode: false,
        }
    }
}

pub(super) const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("es", "Español"),
    ("pt", "Português"),
    ("it", "Italiano"),
    ("zh", "中文"),
    ("ja", "日本語"),
    ("ko", "한국어"),
    ("ru", "Русский"),
];

pub(super) const WALLPAPERS: &[&str] = &[
    "Network Topology",
    "Network Flow",
    "Hardware Aesthetic",
    "Field Focus",
    "Field Depth",
    "Variant Alpha",
    "Variant Beta",
    "Variant Gamma",
    "Variant Delta",
    "Variant Omega",
];

pub(super) fn is_setup_complete() -> bool {
    SETUP_COMPLETE.load(Ordering::Relaxed)
}
pub(super) fn mark_setup_complete() {
    SETUP_COMPLETE.store(true, Ordering::SeqCst);
}
