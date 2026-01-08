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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use super::device::VirtioNetDevice;
use super::{get_virtio_net_device, VIRTIO_NET};

pub struct VirtioNetInterface;
impl crate::drivers::network::stack::NetworkInterface for VirtioNetInterface {
    fn send_packet(&self, frame: &[u8]) -> Result<(), &'static str> {
        if let Some(d) = get_virtio_net_device() {
            d.lock().transmit_packet(frame)
        } else {
            Err("virtio-net not ready")
        }
    }

    fn get_mac_address(&self) -> [u8; 6] {
        if let Some(d) = get_virtio_net_device() {
            d.lock().mac_address
        } else {
            [0; 6]
        }
    }

    fn is_link_up(&self) -> bool {
        VIRTIO_NET.get().is_some()
    }

    fn get_stats(&self) -> crate::drivers::network::stack::NetworkStats {
        if let Some(dev) = get_virtio_net_device() {
            let s = &dev.lock().stats;
            crate::drivers::network::stack::NetworkStats {
                rx_packets: AtomicU64::new(s.rx_packets.load(Ordering::Relaxed)),
                tx_packets: AtomicU64::new(s.tx_packets.load(Ordering::Relaxed)),
                rx_bytes: AtomicU64::new(s.rx_bytes.load(Ordering::Relaxed)),
                tx_bytes: AtomicU64::new(s.tx_bytes.load(Ordering::Relaxed)),
                active_sockets: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(s.rx_errors.load(Ordering::Relaxed)),
                arp_lookups: AtomicU64::new(0),
            }
        } else {
            crate::drivers::network::stack::NetworkStats::default()
        }
    }
}

pub struct VirtioSmolBridge;

impl crate::network::stack::SmolDevice for VirtioSmolBridge {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        if let Some(dev) = get_virtio_net_device() {
            let packets = dev.lock().receive_packets();
            packets.into_iter().next()
        } else {
            None
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        if let Some(dev) = get_virtio_net_device() {
            dev.lock().transmit_packet(frame).map_err(|_| ())
        } else {
            Err(())
        }
    }

    fn mac(&self) -> [u8; 6] {
        if let Some(dev) = get_virtio_net_device() {
            dev.lock().mac_address
        } else {
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        }
    }

    fn link_mtu(&self) -> usize {
        super::constants::MAX_MTU
    }
}

pub static VIRTIO_SMOL_BRIDGE: VirtioSmolBridge = VirtioSmolBridge;

pub fn register_with_smoltcp() {
    crate::network::stack::register_device(&VIRTIO_SMOL_BRIDGE);
}

#[no_mangle]
pub extern "C" fn virtio_net_isr_handler() {
    if let Some(dev) = get_virtio_net_device() {
        let d = dev.lock();

        let packets = d.receive_packets();
        for p in packets {
            let _ = crate::drivers::network::stack::receive_packet(&p);
        }

        d.reclaim_tx();
        d.ack_interrupt();
    }

    crate::arch::x86_64::interrupt::apic::send_eoi();
}

pub fn poll_receive() -> Vec<Vec<u8>> {
    if let Some(dev) = get_virtio_net_device() {
        let d = dev.lock();
        let packets = d.receive_packets();
        d.reclaim_tx();
        packets
    } else {
        Vec::new()
    }
}

pub fn poll_transmit(frame: &[u8]) -> Result<(), &'static str> {
    if let Some(dev) = get_virtio_net_device() {
        dev.lock().transmit_packet(frame)
    } else {
        Err("virtio-net: not initialized")
    }
}

pub fn get_mac_address() -> Option<[u8; 6]> {
    get_virtio_net_device().map(|d| d.lock().mac_address)
}

pub fn is_device_ready() -> bool {
    VIRTIO_NET.get().is_some()
}

pub fn get_stats_snapshot() -> Option<super::stats::NetworkStatsSnapshot> {
    get_virtio_net_device().map(|d| d.lock().stats.snapshot())
}

pub fn enable_mac_filter(enabled: bool) {
    if let Some(dev) = get_virtio_net_device() {
        dev.lock().set_mac_filter_enabled(enabled);
    }
}

pub fn add_mac_filter(mac: [u8; 6]) -> Result<(), &'static str> {
    if let Some(dev) = get_virtio_net_device() {
        dev.lock()
            .add_allowed_mac(mac)
            .map_err(|e| e.as_str())
    } else {
        Err("virtio-net: not initialized")
    }
}
