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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static NETWORK_TYPE: AtomicU8 = AtomicU8::new(0);
static WIFI_SIGNAL: AtomicU8 = AtomicU8::new(0);
static HAS_IP: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NetworkType {
    None = 0,
    Ethernet = 1,
    Wifi = 2,
}

#[derive(Clone, Copy, PartialEq)]
pub enum NetworkState {
    Disconnected,
    Connecting,
    Connected,
    NoInternet,
}

pub fn get_network_type() -> NetworkType {
    match NETWORK_TYPE.load(Ordering::Relaxed) {
        1 => NetworkType::Ethernet,
        2 => NetworkType::Wifi,
        _ => NetworkType::None,
    }
}

pub fn get_wifi_signal() -> u8 {
    WIFI_SIGNAL.load(Ordering::Relaxed)
}
pub fn has_ip_address() -> bool {
    HAS_IP.load(Ordering::Relaxed)
}

pub fn get_network_state() -> NetworkState {
    let net_type = get_network_type();
    if net_type == NetworkType::None {
        return NetworkState::Disconnected;
    }
    if !has_ip_address() {
        return NetworkState::NoInternet;
    }
    NetworkState::Connected
}

pub fn update_network_status() {
    let has_eth = crate::drivers::e1000::is_present();
    let has_wifi = check_wifi_present();
    let ip = crate::network::stack::get_current_ipv4();
    HAS_IP.store(ip.is_some(), Ordering::Relaxed);
    if has_eth && ip.is_some() {
        NETWORK_TYPE.store(NetworkType::Ethernet as u8, Ordering::Relaxed);
    } else if has_wifi {
        NETWORK_TYPE.store(NetworkType::Wifi as u8, Ordering::Relaxed);
        WIFI_SIGNAL.store(get_wifi_rssi(), Ordering::Relaxed);
    } else if has_eth {
        NETWORK_TYPE.store(NetworkType::Ethernet as u8, Ordering::Relaxed);
    } else {
        NETWORK_TYPE.store(NetworkType::None as u8, Ordering::Relaxed);
    }
}

fn check_wifi_present() -> bool {
    crate::drivers::pci::find_device_by_class(0x02, 0x80).is_some()
}

fn get_wifi_rssi() -> u8 {
    let rssi = -50i8;
    rssi_to_bars(rssi)
}

fn rssi_to_bars(rssi: i8) -> u8 {
    match rssi {
        -50..=0 => 4,
        -60..=-51 => 3,
        -70..=-61 => 2,
        -80..=-71 => 1,
        _ => 0,
    }
}

pub fn get_ip_string() -> [u8; 16] {
    let mut buf = [0u8; 16];
    if let Some(ip) = crate::network::stack::get_current_ipv4() {
        let octets = ip.0;
        let mut pos = 0;
        for (i, &octet) in octets.iter().enumerate() {
            pos += write_u8(&mut buf[pos..], octet);
            if i < 3 && pos < 15 {
                buf[pos] = b'.';
                pos += 1;
            }
        }
    }
    buf
}

fn write_u8(buf: &mut [u8], val: u8) -> usize {
    if val >= 100 {
        buf[0] = b'0' + val / 100;
        buf[1] = b'0' + (val / 10) % 10;
        buf[2] = b'0' + val % 10;
        3
    } else if val >= 10 {
        buf[0] = b'0' + val / 10;
        buf[1] = b'0' + val % 10;
        2
    } else {
        buf[0] = b'0' + val;
        1
    }
}

pub fn init() {
    update_network_status();
}
