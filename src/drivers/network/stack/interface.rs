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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;
use spin::{Mutex, RwLock};

pub trait NetworkInterface: Send + Sync + 'static {
    fn send_packet(&self, frame: &[u8]) -> Result<(), &'static str>;
    fn get_mac_address(&self) -> [u8; 6];
    fn is_link_up(&self) -> bool;
    fn get_stats(&self) -> NetworkStats;
    fn mtu(&self) -> usize {
        1500
    }
    fn name(&self) -> &'static str {
        "iface"
    }
}

#[derive(Default)]
pub struct NetworkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub active_sockets: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub arp_lookups: AtomicU64,
}

pub(super) static IFACES: Mutex<BTreeMap<&'static str, Arc<dyn NetworkInterface>>> =
    Mutex::new(BTreeMap::new());
pub(super) static DEFAULT_IFACE: Mutex<Option<Arc<dyn NetworkInterface>>> = Mutex::new(None);

pub(super) static LOCAL_MAC: RwLock<[u8; 6]> = RwLock::new([0; 6]);
pub(super) static LOCAL_IP: RwLock<[u8; 4]> = RwLock::new([0, 0, 0, 0]);
pub(super) static DEFAULT_GW: RwLock<[u8; 4]> = RwLock::new([0, 0, 0, 0]);

pub fn register_interface(name: &'static str, iface: Arc<dyn NetworkInterface>, make_default: bool) {
    IFACES.lock().insert(name, iface.clone());
    if make_default {
        *DEFAULT_IFACE.lock() = Some(iface.clone());
        *LOCAL_MAC.write() = iface.get_mac_address();
    }
}

pub fn set_default_interface(name: &str) -> Result<(), &'static str> {
    let iface = IFACES.lock().get(name).cloned().ok_or("iface not found")?;
    *DEFAULT_IFACE.lock() = Some(iface);
    Ok(())
}

pub fn get_default_interface() -> Option<Arc<dyn NetworkInterface>> {
    DEFAULT_IFACE.lock().as_ref().cloned()
}

pub fn set_ipv4(ip: [u8; 4], gw: Option<[u8; 4]>) {
    *LOCAL_IP.write() = ip;
    if let Some(g) = gw {
        *DEFAULT_GW.write() = g;
    }
}

pub fn get_ipv4() -> [u8; 4] {
    *LOCAL_IP.read()
}

pub fn get_mac() -> [u8; 6] {
    *LOCAL_MAC.read()
}
