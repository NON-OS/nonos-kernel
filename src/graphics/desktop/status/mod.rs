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

pub mod battery;
pub mod network;
pub mod render;
pub mod time;

pub use battery::{get_battery_percent, get_battery_state, is_charging, BatteryState};
pub use network::{
    get_network_state, get_network_type, get_wifi_signal, NetworkState, NetworkType,
};
pub use render::{draw_battery_icon, draw_network_icon};
pub use time::{get_date_string, get_time_string, get_unix_timestamp};
