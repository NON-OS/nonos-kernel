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

use core::ptr;

use super::device::VirtioNetDevice;
use super::error::VirtioNetError;
use super::header::VirtioNetHeader;
use super::validation;

impl VirtioNetDevice {
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

    pub fn reclaim_tx(&self) {
        let mut txq = self.tx_queue.lock();
        for (desc, _len) in txq.get_used_buffers() {
            if let Some(buf) = txq.take_tx_owner(desc) {
                buf.lock().release();
            }
            txq.free_descriptors.push_back(desc);
        }
    }
}
