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

use alloc::{sync::Arc, vec, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::Ordering;
use spin::Mutex;

use super::buffer::PacketBuffer;
use super::constants::*;
use super::device::VirtioNetDevice;
use super::error::VirtioNetError;
use super::header::VirtioNetHeader;
use super::validation;
use super::virtqueue::VirtQueue;

impl VirtioNetDevice {
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
}
