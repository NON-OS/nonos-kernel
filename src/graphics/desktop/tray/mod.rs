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

mod bluetooth;
mod control;
mod items;
mod render;
mod sound;
mod state;
mod wifi;

pub use render::draw;
pub use state::{close_all, get_active, handle_click, is_any_open, toggle, TrayMenu};

pub use bluetooth::{get_bluetooth_devices, pair_device, unpair_device};
pub use control::{get_brightness, get_do_not_disturb, set_brightness, toggle_do_not_disturb};
pub use sound::{get_output_device, get_volume, set_output_device, set_volume};
pub use wifi::{connect_to_network, get_wifi_networks, scan_networks, WifiNetwork};
