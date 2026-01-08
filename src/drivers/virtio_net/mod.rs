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

pub mod buffer;
pub mod constants;
pub mod device;
pub mod dma;
pub mod error;
pub mod header;
pub mod interface;
pub mod modern_regs;
pub mod rate_limiter;
pub mod stats;
pub mod validation;
pub mod virtqueue;

#[cfg(test)]
mod tests;

pub use buffer::PacketBuffer;
pub use constants::*;
pub use device::VirtioNetDevice;
pub use error::VirtioNetError;
pub use header::VirtioNetHeader;
pub use interface::{VirtioNetInterface, VirtioSmolBridge, VIRTIO_SMOL_BRIDGE};
pub use rate_limiter::{RateLimiter, RateLimiterStats};
pub use stats::{NetworkStats, NetworkStatsSnapshot};
pub use validation::EtherType;
pub use virtqueue::{VirtQueue, VirtqDesc, VirtqUsedElem};

use alloc::sync::Arc;
use spin::Mutex;

pub static VIRTIO_NET: spin::Once<Arc<Mutex<VirtioNetDevice>>> = spin::Once::new();
pub fn init_virtio_net() -> Result<(), &'static str> {
    let devs = crate::drivers::pci::scan_and_collect();
    for d in devs {
        if d.vendor_id() == constants::VIRTIO_VENDOR_ID
            && (d.device_id_value() == constants::VIRTIO_NET_DEVICE_ID_TRANSITIONAL
                || d.device_id_value() == constants::VIRTIO_NET_DEVICE_ID_MODERN)
        {
            crate::log::info!(
                "virtio-net at {:02x}:{:02x}.{}",
                d.bus(),
                d.device(),
                d.function()
            );

            let mut nic = VirtioNetDevice::new(d)?;
            let _ = nic.setup_interrupts();

            let arc = Arc::new(Mutex::new(nic));
            VIRTIO_NET.call_once(|| arc.clone());

            let mac = arc.lock().mac_address;
            crate::log::info!(
                "virtio-net MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            crate::drivers::network::stack::register_interface(
                "eth0",
                Arc::new(interface::VirtioNetInterface),
                true,
            );

            crate::network::init_network_stack();
            interface::register_with_smoltcp();
            crate::log::info!("virtio-net: Registered with smoltcp network stack");

            return Ok(());
        }
    }

    Err("virtio-net: no device found")
}

pub fn get_virtio_net_device() -> Option<Arc<Mutex<VirtioNetDevice>>> {
    VIRTIO_NET.get().cloned()
}

extern "x86-interrupt" fn virtio_net_isr(_: crate::arch::x86_64::InterruptStackFrame) {
    super_virtio_isr();
}

#[no_mangle]
pub extern "C" fn super_virtio_isr() {
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

pub fn transmit(frame: &[u8]) -> Result<(), &'static str> {
    interface::poll_transmit(frame)
}

pub fn receive() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    interface::poll_receive()
}

pub fn mac_address() -> Option<[u8; 6]> {
    interface::get_mac_address()
}

pub fn is_ready() -> bool {
    interface::is_device_ready()
}

pub fn statistics() -> Option<NetworkStatsSnapshot> {
    interface::get_stats_snapshot()
}
