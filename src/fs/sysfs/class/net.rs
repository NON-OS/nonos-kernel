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

extern crate alloc;

use super::register_class;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;

static mut NET_CLASS_INO: u64 = 0;

pub fn init_net_class() {
    unsafe {
        NET_CLASS_INO = register_class("net");
    }
}

pub fn register_net_device(name: &str, mac: [u8; 6], mtu: u32) -> u64 {
    let parent = unsafe { NET_CLASS_INO };
    let ino = register_kobject(name, KobjectType::Device, parent);
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    register_attribute(ino, SysfsAttribute::readonly("address", move || mac_str.clone()));
    register_attribute(ino, SysfsAttribute::readonly("mtu", move || format!("{}\n", mtu)));
    register_attribute(ino, SysfsAttribute::readonly("operstate", || String::from("up\n")));
    register_attribute(ino, SysfsAttribute::readonly("carrier", || String::from("1\n")));
    register_attribute(ino, SysfsAttribute::readonly("speed", || String::from("1000\n")));
    register_attribute(ino, SysfsAttribute::readonly("duplex", || String::from("full\n")));
    register_attribute(ino, SysfsAttribute::readonly("type", || String::from("1\n")));
    register_attribute(ino, SysfsAttribute::readonly("flags", || String::from("0x1043\n")));
    ino
}

pub fn get_net_devices() -> alloc::vec::Vec<String> {
    crate::network::list_interfaces().iter().map(|i| i.name.clone()).collect()
}

pub fn get_net_statistics(name: &str) -> Option<NetStats> {
    crate::network::get_interface(name).map(|i| NetStats {
        rx_bytes: i.stats.rx_bytes,
        tx_bytes: i.stats.tx_bytes,
        rx_packets: i.stats.rx_packets,
        tx_packets: i.stats.tx_packets,
    })
}

pub struct NetStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}
