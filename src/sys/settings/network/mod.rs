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

pub mod api;
mod block;
pub mod helpers;
mod load;
pub mod persist;
mod save;
pub mod serialize;
pub mod state;
pub mod types;
pub mod wifi;

pub use api::{
    apply_settings_to_stack, check_network_status, get_privacy_mode, get_settings, get_socks_port,
    init, is_mac_randomization_enabled, is_onion_enabled, is_socks_enabled,
    is_transparent_proxy_enabled, set_mac_randomization_enabled, set_onion_enabled,
    set_privacy_mode, set_socks_enabled, set_socks_port, set_transparent_proxy_enabled,
    update_settings, NetworkStatus,
};
pub use persist::{
    load_from_disk, needs_save, save_to_disk, NETWORK_SETTINGS_FILENAME, WIFI_NETWORKS_FILENAME,
};
pub use serialize::{deserialize_settings, serialize_settings};
pub use types::{NetworkSettings, SavedNetwork, MAX_PASSWORD_LEN, MAX_SAVED_NETWORKS};
pub use wifi::{
    get_saved_networks, get_saved_password, remove_saved_network, save_wifi_network,
    set_network_priority,
};
