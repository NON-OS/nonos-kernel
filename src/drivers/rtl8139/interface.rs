// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::vec::Vec;
use super::{get_rtl8139_device, MAX_MTU};

pub struct Rtl8139SmolBridge;

impl crate::network::stack::SmolDevice for Rtl8139SmolBridge {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        if let Some(dev) = get_rtl8139_device() {
            let packets = dev.lock().receive();
            packets.into_iter().next()
        } else {
            None
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        if let Some(dev) = get_rtl8139_device() {
            dev.lock().transmit(frame).map_err(|_| ())
        } else {
            Err(())
        }
    }

    fn mac(&self) -> [u8; 6] {
        if let Some(dev) = get_rtl8139_device() {
            dev.lock().mac_address
        } else {
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x03]
        }
    }

    fn link_mtu(&self) -> usize {
        MAX_MTU
    }
}

pub static RTL8139_SMOL_BRIDGE: Rtl8139SmolBridge = Rtl8139SmolBridge;

pub fn register_with_network_stack() {
    crate::network::stack::register_device(&RTL8139_SMOL_BRIDGE);
    crate::log::info!("rtl8139: Registered with network stack");
}

#[derive(Debug, Clone, Default)]
pub struct Rtl8139Stats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub link_up: bool,
    pub link_speed: u16,
}

impl Rtl8139Stats {
    pub fn from_device() -> Option<Self> {
        let dev = get_rtl8139_device()?;
        let guard = dev.lock();
        let (rx_packets, rx_bytes, rx_errors) = guard.get_rx_stats();
        let (tx_packets, tx_bytes, tx_errors) = guard.get_tx_stats();

        Some(Self {
            rx_packets,
            tx_packets,
            rx_bytes,
            tx_bytes,
            rx_errors,
            tx_errors,
            link_up: guard.link_up,
            link_speed: guard.link_speed,
        })
    }

    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }
}
