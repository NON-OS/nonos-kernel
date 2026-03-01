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

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::AtomicU64;
use spin::Mutex;

use crate::drivers::pci::{PciBar, PciDevice};

use super::buffer::PacketBuffer;
use super::constants::*;
use super::modern_regs::VirtioModernRegs;
use super::rate_limiter::RateLimiter;
use super::stats::NetworkStats;
use super::virtqueue::VirtQueue;

pub struct VirtioNetDevice {
    pub pci_device: PciDevice,
    pub legacy_bar: Option<PciBar>,
    pub(super) modern: Option<VirtioModernRegs>,
    pub mac_address: [u8; 6],
    pub features: u32,
    pub rx_queue: Mutex<VirtQueue>,
    pub tx_queue: Mutex<VirtQueue>,
    pub ctrl_queue: Option<Mutex<VirtQueue>>,
    pub rx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,
    pub tx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,
    pub stats: NetworkStats,
    pub interrupt_vector: u8,
    pub(super) rx_rate_limiter: RateLimiter,
    pub(super) tx_rate_limiter: RateLimiter,
    pub(super) mac_filter_enabled: AtomicU64,
    pub(super) allowed_macs: Mutex<Vec<[u8; 6]>>,
}

impl VirtioNetDevice {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        if pci_device.vendor_id != VIRTIO_VENDOR_ID {
            return Err("virtio-net: wrong vendor");
        }

        if pci_device.device_id != VIRTIO_NET_DEVICE_ID_TRANSITIONAL
            && pci_device.device_id != VIRTIO_NET_DEVICE_ID_MODERN
        {
            return Err("virtio-net: wrong device id");
        }

        let modern = VirtioModernRegs::map(&pci_device);
        let legacy_bar = if modern.is_none() {
            pci_device.get_bar(0).cloned()
        } else {
            None
        };

        let (mac, features) = if let Some(ref regs) = modern {
            Self::init_modern(regs)?
        } else {
            Self::init_legacy(&legacy_bar)?
        };

        let rxq = Mutex::new(VirtQueue::new(DEFAULT_QUEUE_SIZE)?);
        let txq = Mutex::new(VirtQueue::new(DEFAULT_QUEUE_SIZE)?);
        let ctrlq = Some(Mutex::new(VirtQueue::new(CTRL_QUEUE_SIZE)?));

        let mut dev = Self {
            pci_device,
            legacy_bar,
            modern,
            mac_address: mac,
            features,
            rx_queue: rxq,
            tx_queue: txq,
            ctrl_queue: ctrlq,
            rx_buffers: Mutex::new(Vec::new()),
            tx_buffers: Mutex::new(Vec::new()),
            stats: NetworkStats::default(),
            interrupt_vector: 0,
            rx_rate_limiter: RateLimiter::new(RATE_LIMIT_RX_PPS, RATE_LIMIT_BURST_RX),
            tx_rate_limiter: RateLimiter::new(RATE_LIMIT_TX_PPS, RATE_LIMIT_BURST_TX),
            mac_filter_enabled: AtomicU64::new(0),
            allowed_macs: Mutex::new(Vec::new()),
        };

        if dev.modern.is_some() {
            dev.setup_queues_modern()?;
        } else {
            dev.setup_queues_legacy()?;
        }

        dev.allocate_buffers()?;
        dev.refill_rx(INITIAL_RX_PRIME_COUNT);
        dev.set_status_driver_ok();

        Ok(dev)
    }
}
