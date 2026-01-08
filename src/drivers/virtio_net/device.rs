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

use alloc::{sync::Arc, vec, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::PhysAddr;
use crate::drivers::pci::{PciBar, PciDevice};
use crate::interrupts::register_interrupt_handler;
use super::buffer::PacketBuffer;
use super::constants::*;
use super::error::VirtioNetError;
use super::header::VirtioNetHeader;
use super::modern_regs::VirtioModernRegs;
use super::rate_limiter::RateLimiter;
use super::stats::NetworkStats;
use super::validation;
use super::virtqueue::VirtQueue;
pub struct VirtioNetDevice {
    pub pci_device: PciDevice,
    pub legacy_bar: Option<PciBar>,
    modern: Option<VirtioModernRegs>,
    pub mac_address: [u8; 6],
    pub features: u32,
    pub rx_queue: Mutex<VirtQueue>,
    pub tx_queue: Mutex<VirtQueue>,
    pub ctrl_queue: Option<Mutex<VirtQueue>>,
    pub rx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,
    pub tx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,
    pub stats: NetworkStats,
    pub interrupt_vector: u8,
    rx_rate_limiter: RateLimiter,
    tx_rate_limiter: RateLimiter,
    mac_filter_enabled: AtomicU64,
    allowed_macs: Mutex<Vec<[u8; 6]>>,
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

    fn init_modern(regs: &VirtioModernRegs) -> Result<([u8; 6], u32), &'static str> {
        // SAFETY: regs.common is valid MMIO memory from PCI capability parsing
        unsafe {
            let common_ptr = regs.common.as_ptr();

            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
            );

            ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).device_feature_select), 0);
            let devf = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_feature));

            let supported = (1 << VIRTIO_NET_F_MAC)
                | (1 << VIRTIO_NET_F_STATUS)
                | (1 << VIRTIO_NET_F_CTRL_VQ);

            ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).driver_feature_select), 0);
            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).driver_feature),
                devf & supported,
            );

            let s0 = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_status));
            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).device_status),
                s0 | VIRTIO_STATUS_FEATURES_OK,
            );

            let s1 = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_status));
            if (s1 & VIRTIO_STATUS_FEATURES_OK) == 0 {
                return Err("virtio-net: FEATURES_OK rejected");
            }

            let mac = regs.read_mac_address();

            Ok((mac, devf & supported))
        }
    }

    fn init_legacy(legacy_bar: &Option<PciBar>) -> Result<([u8; 6], u32), &'static str> {
        let bar = legacy_bar.as_ref().ok_or("virtio-net: missing legacy BAR")?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("virtio-net: legacy needs MMIO BAR"),
        };

        // SAFETY: base points to valid MMIO memory from BAR
        unsafe {
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, 0);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, VIRTIO_STATUS_ACKNOWLEDGE);

            let cur = ptr::read_volatile((base + LEG_STATUS) as *const u8);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, cur | VIRTIO_STATUS_DRIVER);

            let devf = ptr::read_volatile((base + LEG_HOST_FEATURES) as *const u32);
            let supported = (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_STATUS);
            ptr::write_volatile((base + LEG_GUEST_FEATURES) as *mut u32, devf & supported);

            let c2 = ptr::read_volatile((base + LEG_STATUS) as *const u8);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, c2 | VIRTIO_STATUS_FEATURES_OK);

            let mut mac = [0u8; 6];
            for i in 0..6 {
                mac[i] = ptr::read_volatile((base + LEG_MAC + i) as *const u8);
            }

            Ok((mac, devf & supported))
        }
    }

    fn setup_queues_modern(&mut self) -> Result<(), &'static str> {
        let regs = self.modern.as_ref().ok_or("virtio-net: modern interface not available")?;

        // SAFETY: regs.common is valid MMIO memory
        unsafe {
            let common_ptr = regs.common.as_ptr();

            for qidx in [Q_RX, Q_TX] {
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_select), qidx);

                let qmax = ptr::read_unaligned(ptr::addr_of!((*common_ptr).queue_size));
                if qmax == 0 {
                    return Err("virtio-net: queue not available");
                }

                let qsize = core::cmp::min(DEFAULT_QUEUE_SIZE, qmax);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_size), qsize);

                let (desc, avail, used) = match qidx {
                    Q_RX => {
                        let q = self.rx_queue.get_mut();
                        (
                            q.desc_table_phys.as_u64(),
                            q.avail_ring_phys.as_u64(),
                            q.used_ring_phys.as_u64(),
                        )
                    }
                    Q_TX => {
                        let q = self.tx_queue.get_mut();
                        (
                            q.desc_table_phys.as_u64(),
                            q.avail_ring_phys.as_u64(),
                            q.used_ring_phys.as_u64(),
                        )
                    }
                    _ => unreachable!(),
                };

                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_desc), desc);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_avail), avail);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_used), used);

                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_enable), 1);

                let noff = ptr::read_unaligned(ptr::addr_of!((*common_ptr).queue_notify_off));
                let naddr = regs.queue_notify_addr(noff);

                match qidx {
                    Q_RX => self.rx_queue.get_mut().set_notify_addr(naddr),
                    Q_TX => self.tx_queue.get_mut().set_notify_addr(naddr),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn setup_queues_legacy(&mut self) -> Result<(), &'static str> {
        let bar = self.legacy_bar.as_ref().ok_or("virtio-net: legacy BAR missing")?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("virtio-net: legacy needs MMIO BAR"),
        };

        // SAFETY: base points to valid MMIO memory from BAR
        unsafe {
            for qidx in [Q_RX, Q_TX] {
                ptr::write_volatile((base + LEG_QUEUE_SEL) as *mut u16, qidx);

                let qmax = ptr::read_volatile((base + LEG_QUEUE_NUM) as *const u16);
                if qmax == 0 {
                    return Err("virtio-net: legacy queue not available");
                }

                let queue_phys = match qidx {
                    Q_RX => self.rx_queue.get_mut().desc_table_phys.as_u64(),
                    Q_TX => self.tx_queue.get_mut().desc_table_phys.as_u64(),
                    _ => unreachable!(),
                };

                let pfn = (queue_phys >> 12) as u32;
                ptr::write_volatile((base + LEG_QUEUE_PFN) as *mut u32, pfn);

                let notify_addr = (base + LEG_NOTIFY) as u64;
                match qidx {
                    Q_RX => self.rx_queue.get_mut().set_notify_addr(notify_addr),
                    Q_TX => self.tx_queue.get_mut().set_notify_addr(notify_addr),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn allocate_buffers(&mut self) -> Result<(), &'static str> {
        {
            let mut rx = self.rx_buffers.lock();
            for _ in 0..DEFAULT_RX_BUFFER_COUNT {
                rx.push(Arc::new(Mutex::new(PacketBuffer::new(RX_BUFFER_SIZE)?)));
            }
        }

        {
            let mut tx = self.tx_buffers.lock();
            for _ in 0..DEFAULT_TX_BUFFER_COUNT {
                tx.push(Arc::new(Mutex::new(PacketBuffer::new(TX_BUFFER_SIZE)?)));
            }
        }

        Ok(())
    }

    fn set_status_driver_ok(&mut self) {
        if let Some(ref regs) = self.modern {
            // SAFETY: regs.common is valid MMIO memory
            unsafe {
                let common_ptr = regs.common.as_ptr();
                let s = ptr::read_unaligned(&(*common_ptr).device_status);
                ptr::write_unaligned(
                    &mut (*common_ptr).device_status,
                    s | VIRTIO_STATUS_DRIVER_OK,
                );
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            let base = address.as_u64() as usize;
            // SAFETY: base points to valid MMIO memory from BAR
            unsafe {
                let s = ptr::read_volatile((base + LEG_STATUS) as *const u8);
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, s | VIRTIO_STATUS_DRIVER_OK);
            }
        }
    }

    pub fn setup_interrupts(&mut self) -> Result<(), &'static str> {
        let vector = crate::interrupts::allocate_vector()
            .ok_or("Failed to allocate interrupt vector")?;

        fn isr_wrapper(_frame: crate::arch::x86_64::InterruptStackFrame) {
            super::super_virtio_isr();
        }

        register_interrupt_handler(vector, isr_wrapper)?;
        self.pci_device
            .configure_msix(vector)
            .map_err(|_| "MSI-X configuration failed")?;
        self.interrupt_vector = vector;

        Ok(())
    }

    pub fn transmit_packet(&self, payload: &[u8]) -> Result<(), &'static str> {
        match self.transmit_packet_validated(payload) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stats.record_error(e);
                self.stats.record_tx_error();

                if e.is_security_relevant() {
                    crate::log_warn!("virtio-net: TX error: {}", e.as_str());
                }

                Err(e.as_str())
            }
        }
    }

    fn transmit_packet_validated(&self, payload: &[u8]) -> Result<(), VirtioNetError> {
        validation::validate_packet_size(payload.len(), false)?;
        validation::validate_ethernet_frame(payload)?;

        let current_time = crate::time::timestamp_millis();
        self.tx_rate_limiter.check_rate_limit(current_time)?;

        let buf_arc = {
            let v = self.tx_buffers.lock();
            v.get(0).cloned().ok_or(VirtioNetError::NoBuffersAvailable)?
        };

        let hdr = VirtioNetHeader::simple();
        hdr.validate()?;

        let hdr_bytes = hdr.as_bytes();
        let total = hdr_bytes.len() + payload.len();

        {
            let mut b = buf_arc.lock();
            if total > b.capacity() {
                return Err(VirtioNetError::BufferTooSmall);
            }

            b.acquire()?;

            // SAFETY: buffer pointers are valid DMA memory
            unsafe {
                ptr::copy_nonoverlapping(
                    hdr_bytes.as_ptr(),
                    b.virt().as_mut_ptr::<u8>(),
                    hdr_bytes.len(),
                );
                ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    b.virt().as_mut_ptr::<u8>().add(hdr_bytes.len()),
                    payload.len(),
                );
            }
            b.set_len(total);
        }

        let mut txq = self.tx_queue.lock();
        let chain = txq
            .alloc_desc_chain(1)
            .ok_or(VirtioNetError::NoDescriptorsAvailable)?;

        validation::validate_chain_length(&chain)?;
        validation::validate_descriptor_index(chain[0], txq.queue_size)?;

        let idx = chain[0] as usize;
        let phys_addr = buf_arc.lock().phys();

        validation::validate_dma_address(phys_addr, total)?;

        // SAFETY: desc_table pointer is valid DMA memory, idx is bounds-checked
        unsafe {
            let d = &mut *txq.desc_table.add(idx);
            d.addr = phys_addr.as_u64();
            d.len = total as u32;
            d.flags = 0;
            d.next = 0;
        }

        txq.set_tx_owner(chain[0], buf_arc);
        txq.add_to_avail_ring(chain[0]);
        txq.kick();

        self.stats.record_tx(payload.len());

        Ok(())
    }

    pub fn receive_packets(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut rxq = self.rx_queue.lock();
        let current_time = crate::time::timestamp_millis();

        for (desc, len) in rxq.get_used_buffers() {
            match self.process_rx_packet(desc, len, &mut rxq, current_time) {
                Ok(Some(pkt)) => {
                    self.stats.record_rx(pkt.len());
                    out.push(pkt);
                }
                Ok(None) => {
                    self.stats.record_rx_drop();
                }
                Err(e) => {
                    self.stats.record_error(e);
                    self.stats.record_rx_error();

                    if e.is_security_relevant() {
                        if self.stats.rate_limit_violations.load(Ordering::Relaxed) % 100 == 0 {
                            crate::log_warn!("virtio-net: RX error: {}", e.as_str());
                        }
                    }
                }
            }
        }

        rxq.kick();
        out
    }

    fn process_rx_packet(
        &self,
        desc: u16,
        len: u32,
        rxq: &mut VirtQueue,
        current_time: u64,
    ) -> Result<Option<Vec<u8>>, VirtioNetError> {
        validation::validate_descriptor_index(desc, rxq.queue_size)?;

        if len < mem::size_of::<VirtioNetHeader>() as u32 {
            self.rearm_rx_buffer(desc, rxq)?;
            return Err(VirtioNetError::PacketTooSmall);
        }

        self.rx_rate_limiter.check_rate_limit(current_time)?;

        let buf = rxq.take_rx_owner(desc).ok_or(VirtioNetError::QueueError)?;

        // SAFETY: buffer pointer is valid DMA memory
        let hdr = unsafe {
            let hdr_ptr = buf.lock().virt().as_ptr::<VirtioNetHeader>();
            ptr::read(hdr_ptr)
        };
        hdr.validate()?;

        let pkt_len = (len as usize) - mem::size_of::<VirtioNetHeader>();

        if pkt_len < MIN_ETHERNET_FRAME || pkt_len > MAX_ETHERNET_FRAME {
            self.rearm_rx_buffer_with_buf(desc, buf, rxq)?;
            return Err(VirtioNetError::InvalidPacketSize);
        }

        let mut pkt = vec![0u8; pkt_len];
        // SAFETY: buffer pointer is valid DMA memory
        unsafe {
            ptr::copy_nonoverlapping(
                buf.lock()
                    .virt()
                    .as_ptr::<u8>()
                    .add(mem::size_of::<VirtioNetHeader>()),
                pkt.as_mut_ptr(),
                pkt_len,
            );
        }

        validation::validate_ethernet_frame(&pkt)?;

        if self.mac_filter_enabled.load(Ordering::Relaxed) == 1 {
            if !self.check_mac_filter(&pkt) {
                buf.lock().zero();
                self.rearm_rx_buffer_with_buf(desc, buf, rxq)?;
                return Ok(None);
            }
        }

        buf.lock().zero();
        self.rearm_rx_buffer_with_buf(desc, buf, rxq)?;

        Ok(Some(pkt))
    }

    fn rearm_rx_buffer(&self, desc: u16, rxq: &mut VirtQueue) -> Result<(), VirtioNetError> {
        if let Some(buf) = rxq.take_rx_owner(desc) {
            self.rearm_rx_buffer_with_buf(desc, buf, rxq)
        } else {
            Err(VirtioNetError::QueueError)
        }
    }

    fn rearm_rx_buffer_with_buf(
        &self,
        desc: u16,
        buf: Arc<Mutex<PacketBuffer>>,
        rxq: &mut VirtQueue,
    ) -> Result<(), VirtioNetError> {
        let phys = buf.lock().phys();
        validation::validate_dma_address(phys, RX_BUFFER_SIZE)?;

        // SAFETY: desc_table pointer is valid DMA memory, desc is bounds-checked by caller
        unsafe {
            let d = &mut *rxq.desc_table.add(desc as usize);
            d.addr = phys.as_u64();
            d.len = RX_BUFFER_SIZE as u32;
            d.flags = VIRTQ_DESC_F_WRITE;
            d.next = 0;
        }

        rxq.set_rx_owner(desc, buf);
        rxq.add_to_avail_ring(desc);

        Ok(())
    }

    fn check_mac_filter(&self, packet: &[u8]) -> bool {
        if packet.len() < 12 {
            return false;
        }

        let src_mac: [u8; 6] = [
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
        ];

        let allowed = self.allowed_macs.lock();
        if allowed.is_empty() {
            return true;
        }

        allowed.iter().any(|mac| mac == &src_mac)
    }

    pub fn reclaim_tx(&self) {
        let mut txq = self.tx_queue.lock();
        for (desc, _len) in txq.get_used_buffers() {
            if let Some(buf) = txq.take_tx_owner(desc) {
                buf.lock().release();
            }
            txq.free_descriptors.push_back(desc);
        }
    }

    pub fn refill_rx(&self, count: usize) {
        let rxb = self.rx_buffers.lock();
        let mut rxq = self.rx_queue.lock();

        for buf in rxb.iter().take(count) {
            if let Some(chain) = rxq.alloc_desc_chain(1) {
                let idx = chain[0] as usize;
                let phys = buf.lock().phys();

                // SAFETY: desc_table pointer is valid DMA memory, idx is from alloc_desc_chain
                unsafe {
                    let d = &mut *rxq.desc_table.add(idx);
                    d.addr = phys.as_u64();
                    d.len = RX_BUFFER_SIZE as u32;
                    d.flags = VIRTQ_DESC_F_WRITE;
                    d.next = 0;
                }

                rxq.set_rx_owner(chain[0], buf.clone());
                rxq.add_to_avail_ring(chain[0]);
            } else {
                break;
            }
        }

        rxq.kick();
    }

    pub fn ack_interrupt(&self) {
        if let Some(ref regs) = self.modern {
            let _ = regs.read_isr();
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            // SAFETY: address points to valid MMIO memory from BAR
            unsafe {
                let _ = ptr::read_volatile((address.as_u64() as usize + LEG_ISR) as *const u8);
            }
        }
    }

    pub fn set_mac_filter_enabled(&self, enabled: bool) {
        self.mac_filter_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Release);
        crate::log::info!(
            "virtio-net: MAC filtering {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    pub fn add_allowed_mac(&self, mac: [u8; 6]) -> Result<(), VirtioNetError> {
        validation::validate_mac_address(&mac)?;
        let mut allowed = self.allowed_macs.lock();
        if !allowed.contains(&mac) {
            allowed.push(mac);
            crate::log::info!(
                "virtio-net: Added MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} to filter",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
        Ok(())
    }

    pub fn remove_allowed_mac(&self, mac: [u8; 6]) {
        let mut allowed = self.allowed_macs.lock();
        allowed.retain(|m| m != &mac);
    }

    pub fn clear_mac_filters(&self) {
        let mut allowed = self.allowed_macs.lock();
        allowed.clear();
    }

    pub fn get_rate_limit_stats(&self) -> (u64, u64) {
        (
            self.rx_rate_limiter.get_violations(),
            self.tx_rate_limiter.get_violations(),
        )
    }

    pub fn print_security_stats(&self) {
        self.stats.snapshot().log_report();
    }

    pub fn deinit(&mut self) {
        if let Some(ref regs) = self.modern {
            // SAFETY: regs.common is valid MMIO memory
            unsafe {
                let common_ptr = regs.common.as_ptr();
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).device_status), 0);
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            let base = address.as_u64() as usize;
            // SAFETY: base points to valid MMIO memory from BAR
            unsafe {
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, 0);
            }
        }

        self.rx_buffers.lock().clear();
        self.tx_buffers.lock().clear();

        crate::log::info!("virtio-net: device deinitialized");
    }
}
