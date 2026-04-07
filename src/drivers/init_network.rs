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

use super::{init_e1000, init_rtl8139, init_rtl8168, init_wifi, print_wifi_status};
use super::virtio_net::init_virtio_net;

pub fn init_network_drivers() {
    crate::log_info!("[NET] Probing for hardware network adapters...");
    let mut eth_count = 0u8;
    if init_e1000().is_ok() { crate::log::logger::log_critical("✓ Intel E1000 Ethernet initialized"); eth_count += 1; }
    if init_rtl8139().is_ok() { crate::log::logger::log_critical("✓ Realtek RTL8139 Ethernet initialized"); eth_count += 1; }
    if init_rtl8168().is_ok() { crate::log::logger::log_critical("✓ Realtek RTL8168 Gigabit Ethernet initialized"); eth_count += 1; }
    if init_virtio_net().is_ok() { crate::log::logger::log_critical("✓ VirtIO-net initialized"); eth_count += 1; }
    if eth_count == 0 {
        crate::log_warn!("[NET] No Ethernet adapters detected - check PCI/drivers");
    } else {
        crate::log_info!("[NET] {} Ethernet adapter(s) ready", eth_count);
    }
    let wifi_count = init_wifi();
    if wifi_count > 0 {
        crate::log_info!("[WIFI] Found {} WiFi adapter(s)", wifi_count);
        print_wifi_status();
    }
}
