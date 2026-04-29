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

use crate::drivers::wifi;
use crate::drivers::wifi::scan::SecurityType;
use core::sync::atomic::{AtomicBool, Ordering};

const MAX_SSID_LEN: usize = 32;

#[derive(Clone, Copy)]
pub struct WifiNetwork {
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: usize,
    pub signal: u8,
    pub secured: bool,
    pub connected: bool,
}

impl WifiNetwork {
    pub const fn empty() -> Self {
        Self { ssid: [0u8; MAX_SSID_LEN], ssid_len: 0, signal: 0, secured: false, connected: false }
    }
}

static WIFI_ENABLED: AtomicBool = AtomicBool::new(true);
static mut CACHED_NETWORKS: [WifiNetwork; 8] = [WifiNetwork::empty(); 8];
static mut NETWORK_COUNT: usize = 0;

pub fn scan_networks() {
    if !wifi::is_available() {
        return;
    }
    if let Ok(results) = wifi::scan() {
        unsafe {
            NETWORK_COUNT = results.len().min(8);
            for (i, result) in results.iter().take(8).enumerate() {
                CACHED_NETWORKS[i] = from_scan_result(result);
            }
        }
    }
}

fn from_scan_result(result: &wifi::ScanResult) -> WifiNetwork {
    let mut net = WifiNetwork::empty();
    net.ssid_len = result.ssid.len().min(MAX_SSID_LEN);
    for i in 0..net.ssid_len {
        net.ssid[i] = result.ssid.as_bytes()[i];
    }
    net.signal = rssi_to_bars(result.rssi);
    net.secured = result.security != SecurityType::Open;
    net.connected = wifi::is_connected() && is_current_ssid(&result.ssid);
    net
}

fn rssi_to_bars(rssi: i8) -> u8 {
    match rssi {
        -50..=0 => 4,
        -60..=-51 => 3,
        -70..=-61 => 2,
        _ => 1,
    }
}

fn is_current_ssid(ssid: &str) -> bool {
    wifi::get_link_info().map(|li| li.ssid == ssid).unwrap_or(false)
}

pub fn get_wifi_networks() -> impl Iterator<Item = &'static WifiNetwork> {
    unsafe { CACHED_NETWORKS[..NETWORK_COUNT].iter() }
}

pub fn connect_to_network(idx: usize) {
    unsafe {
        if idx < NETWORK_COUNT {
            let ssid =
                core::str::from_utf8(&CACHED_NETWORKS[idx].ssid[..CACHED_NETWORKS[idx].ssid_len])
                    .unwrap_or("");
            let _ = wifi::connect(ssid, "");
        }
    }
}

pub(super) fn is_enabled() -> bool {
    WIFI_ENABLED.load(Ordering::Relaxed) && wifi::is_available()
}

pub(super) fn toggle_enabled() {
    let prev = WIFI_ENABLED.load(Ordering::Relaxed);
    WIFI_ENABLED.store(!prev, Ordering::Relaxed);
    if prev {
        let _ = wifi::disconnect();
    }
}

pub(super) fn handle_item_click(item: u8) {
    if item == 0 {
        toggle_enabled();
    } else {
        connect_to_network((item - 1) as usize);
    }
}
