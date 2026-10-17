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

//! The capsule's `settings` module, less everything but the sections and
//! their row tables.

#[path = "../../capsule_settings/src/settings/schema/mod.rs"]
pub mod schema;
#[path = "../../capsule_settings/src/settings/section.rs"]
pub mod section;
// The hover's geometry, over a stand-in for the panel's state.
#[path = "settings_state.rs"]
pub mod state;
#[path = "settings_ui.rs"]
pub mod ui;

// What the Security page says the TPM answered, and the Wi-Fi page's keys
// and refusals: pure tables and mappings, compiled as the capsule has them.
#[path = "../../capsule_settings/src/settings/state/machine_key.rs"]
pub mod machine_key;
#[path = "../../capsule_settings/src/settings/event/wifi_key.rs"]
pub mod wifi_key;
#[path = "../../capsule_settings/src/settings/state/wifi_refusal.rs"]
pub mod wifi_refusal;
