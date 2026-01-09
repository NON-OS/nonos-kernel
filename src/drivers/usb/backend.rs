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

use x86_64::VirtAddr;

pub trait UsbHostBackend: Send + Sync + 'static {
    fn num_ports(&self) -> u8;

    fn control_transfer(
        &self,
        slot_id: u8,
        setup: [u8; 8],
        data_in: Option<&mut [u8]>,
        data_out: Option<&[u8]>,
        timeout_us: u32,
    ) -> Result<usize, &'static str>;

    fn default_slot(&self) -> Option<u8> {
        Some(1)
    }

    fn bulk_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        timeout_us: u32,
    ) -> Result<usize, &'static str>;

    fn interrupt_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        interval: u8,
        timeout_us: u32,
    ) -> Result<usize, &'static str>;
}

pub struct XhciBackend;

impl UsbHostBackend for XhciBackend {
    fn num_ports(&self) -> u8 {
        crate::drivers::xhci::get_controller()
            .map(|c| c.num_ports as u8)
            .unwrap_or(1)
    }

    fn control_transfer(
        &self,
        slot_id: u8,
        setup: [u8; 8],
        data_in: Option<&mut [u8]>,
        data_out: Option<&[u8]>,
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        if let Some(out_data) = data_out {
            let mut temp_buf = alloc::vec![0u8; out_data.len()];
            temp_buf.copy_from_slice(out_data);
            crate::drivers::xhci::control_transfer(slot_id, setup, Some(&mut temp_buf), timeout_us)
        } else {
            crate::drivers::xhci::control_transfer(slot_id, setup, data_in, timeout_us)
        }
    }

    fn default_slot(&self) -> Option<u8> {
        Some(1)
    }

    fn bulk_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        if let Some(ctrl_mutex) = crate::drivers::xhci::XHCI_ONCE.get() {
            let mut ctrl = ctrl_mutex.lock();

            let transfer_len = buffer.len();
            let constraints = crate::memory::dma::DmaConstraints {
                alignment: 64,
                max_segment_size: transfer_len,
                dma32_only: false,
                coherent: true,
            };
            let dma_buf = crate::memory::dma::alloc_dma_coherent(transfer_len, constraints)
                .map_err(|_| "Failed to allocate DMA buffer for bulk transfer")?;

            let is_in = (endpoint & 0x80) != 0;
            if !is_in {
                // SAFETY: source buffer is valid, DMA buffer was just allocated with sufficient size
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        dma_buf.virt_addr.as_mut_ptr::<u8>(),
                        transfer_len
                    );
                }
            }

            let mut bulk_trb = crate::drivers::xhci::Trb::default();
            bulk_trb.d0 = (dma_buf.phys_addr.as_u64() & 0xFFFF_FFFF) as u32;
            bulk_trb.d1 = (dma_buf.phys_addr.as_u64() >> 32) as u32;
            bulk_trb.d2 = transfer_len as u32;
            bulk_trb.d3 = crate::drivers::xhci::TRB_IOC;
            bulk_trb.set_type(crate::drivers::xhci::TRB_TYPE_NORMAL);

            if let Some(ep0) = ctrl.ep0_ring.as_mut() {
                bulk_trb.set_cycle(ep0.cycle());
                let trb_ptr = ep0.enqueue(bulk_trb);

                // SAFETY: MMIO address is valid doorbell register
                unsafe {
                    crate::memory::mmio::mmio_w32(
                        VirtAddr::new((ctrl.db_base + (slot_id as usize) * 4) as u64),
                        endpoint as u32
                    );
                }

                let start_time = crate::time::current_ticks();
                let timeout_ticks = (timeout_us / 1000) as u64;
                let trb_addr = trb_ptr.map_err(|e| e.as_str())?;

                loop {
                    match ctrl.wait_transfer_completion(trb_addr) {
                        Ok(()) => break,
                        Err(_) => {
                            if timeout_us > 0 && crate::time::current_ticks() - start_time > timeout_ticks {
                                return Err("Bulk transfer timeout");
                            }
                            for _ in 0..100 {
                                core::hint::spin_loop();
                            }
                        }
                    }
                }

                if is_in {
                    // SAFETY: DMA buffer contains valid data, destination buffer has sufficient size
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            dma_buf.virt_addr.as_ptr::<u8>(),
                            buffer.as_mut_ptr(),
                            transfer_len
                        );
                    }
                }

                Ok(transfer_len)
            } else {
                Err("EP0 ring not available for bulk transfer")
            }
        } else {
            Err("xHCI controller not initialized")
        }
    }

    fn interrupt_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        interval: u8,
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        if let Some(ctrl_mutex) = crate::drivers::xhci::XHCI_ONCE.get() {
            let mut ctrl = ctrl_mutex.lock();

            let transfer_len = buffer.len();
            let constraints = crate::memory::dma::DmaConstraints {
                alignment: 64,
                max_segment_size: transfer_len,
                dma32_only: false,
                coherent: true,
            };
            let dma_buf = crate::memory::dma::alloc_dma_coherent(transfer_len, constraints)
                .map_err(|_| "Failed to allocate DMA buffer for interrupt transfer")?;

            let is_in = (endpoint & 0x80) != 0;
            if !is_in {
                // SAFETY: source buffer is valid, DMA buffer was just allocated with sufficient size
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        dma_buf.virt_addr.as_mut_ptr::<u8>(),
                        transfer_len
                    );
                }
            }

            let mut int_trb = crate::drivers::xhci::Trb::default();
            int_trb.d0 = (dma_buf.phys_addr.as_u64() & 0xFFFF_FFFF) as u32;
            int_trb.d1 = (dma_buf.phys_addr.as_u64() >> 32) as u32;
            int_trb.d2 = transfer_len as u32;
            int_trb.d3 = crate::drivers::xhci::TRB_IOC;
            int_trb.set_type(crate::drivers::xhci::TRB_TYPE_NORMAL);

            if let Some(ep0) = ctrl.ep0_ring.as_mut() {
                int_trb.set_cycle(ep0.cycle());
                let trb_ptr = ep0.enqueue(int_trb);

                // SAFETY: MMIO address is valid doorbell register
                unsafe {
                    crate::memory::mmio::mmio_w32(
                        VirtAddr::new((ctrl.db_base + (slot_id as usize) * 4) as u64),
                        endpoint as u32
                    );
                }

                let start_time = crate::time::current_ticks();
                let timeout_ticks = timeout_us / 1000;

                loop {
                    match ctrl.wait_transfer_completion(trb_ptr.map_err(|e| e.as_str())?) {
                        Ok(()) => break,
                        Err(_) => {
                            if crate::time::current_ticks() - start_time > timeout_ticks as u64 {
                                return Err("Interrupt transfer timeout");
                            }
                            for _ in 0..(interval as u32 * 1000) {
                                core::hint::spin_loop();
                            }
                        }
                    }
                }

                if is_in {
                    // SAFETY: DMA buffer contains valid data, destination buffer has sufficient size
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            dma_buf.virt_addr.as_ptr::<u8>(),
                            buffer.as_mut_ptr(),
                            transfer_len
                        );
                    }
                }

                Ok(transfer_len)
            } else {
                Err("EP0 ring not available for interrupt transfer")
            }
        } else {
            Err("xHCI controller not initialized")
        }
    }
}
