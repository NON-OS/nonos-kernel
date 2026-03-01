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

pub mod types;
pub mod state;
pub mod api;
pub mod wifi;
pub mod serialize;
pub mod helpers;
mod block;
mod save;
mod load;
pub mod persist;

pub use types::{SavedNetwork, NetworkSettings, MAX_SAVED_NETWORKS, MAX_PASSWORD_LEN};
pub use api::{
    init, get_settings, update_settings, get_privacy_mode, set_privacy_mode,
    is_onion_enabled, set_onion_enabled, is_socks_enabled, set_socks_enabled,
    get_socks_port, set_socks_port, is_transparent_proxy_enabled, set_transparent_proxy_enabled,
    is_mac_randomization_enabled, set_mac_randomization_enabled,
};
pub use wifi::{save_wifi_network, get_saved_networks, get_saved_password, remove_saved_network, set_network_priority};
pub use serialize::{serialize_settings, deserialize_settings};
pub use persist::{save_to_disk, load_from_disk, needs_save, NETWORK_SETTINGS_FILENAME, WIFI_NETWORKS_FILENAME};
