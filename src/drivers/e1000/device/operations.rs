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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::super::constants::*;
use super::super::descriptors::{E1000RxDesc, E1000TxDesc};
use super::core::E1000Device;

impl E1000Device {
    pub fn update_link_status(&mut self) {
        let status_val = self.read_reg(reg::STATUS);
        self.link_up = (status_val & status::LU) != 0;
        self.full_duplex = (status_val & status::FD) != 0;
        self.link_speed = match status_val & status::SPEED_MASK {
            status::SPEED_10 => 10,
            status::SPEED_100 => 100,
            status::SPEED_1000 => 1000,
            _ => 0,
        };

        let ctrl_val = self.read_reg(reg::CTRL);
        self.write_reg(reg::CTRL, ctrl_val | ctrl::SLU | ctrl::ASDE);
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > BUFFER_SIZE {
            return Err("Packet too large");
        }
        if data.len() < MIN_FRAME_SIZE {
            return Err("Packet too small");
        }

        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();
        let desc_idx = self.tx_tail;

        // SAFETY: tx_descs and tx_buffers_virt point to valid DMA memory
        unsafe {
            let desc = &mut *tx_descs.add(desc_idx);

            if desc.status & 0x01 == 0 {
                return Err("TX ring full");
            }

            let buf_ptr = self.tx_buffers_virt[desc_idx].as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());

            desc.length = data.len() as u16;
            desc.cso = 0;
            desc.cmd = tx_cmd::EOP | tx_cmd::IFCS | tx_cmd::RS;
            desc.status = 0;
            desc.css = 0;
            desc.special = 0;
        }

        self.tx_in_flight[desc_idx] = true;

        self.tx_tail = (self.tx_tail + 1) % TX_DESC_COUNT;
        self.write_reg(reg::TDT, self.tx_tail as u32);

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();

        loop {
            let desc_idx = (self.rx_tail + 1) % RX_DESC_COUNT;

            // SAFETY: rx_descs and rx_buffers_virt point to valid DMA memory
            unsafe {
                let desc = &mut *rx_descs.add(desc_idx);

                if !desc.is_done() {
                    break;
                }

                if desc.has_error() {
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                } else if desc.is_eop() && desc.length > 0 {
                    let len = desc.length as usize;
                    if len > BUFFER_SIZE {
                        crate::log_warn!("e1000: RX packet length {} exceeds buffer size", len);
                        self.rx_errors.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let buf_ptr = self.rx_buffers_virt[desc_idx].as_ptr::<u8>();
                        let mut packet = Vec::with_capacity(len);
                        packet.extend_from_slice(core::slice::from_raw_parts(buf_ptr, len));
                        packets.push(packet);

                        self.rx_packets.fetch_add(1, Ordering::Relaxed);
                        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                }

                desc.reset();
            }

            self.rx_tail = desc_idx;
            self.write_reg(reg::RDT, self.rx_tail as u32);
        }

        packets
    }

    pub fn handle_interrupt(&mut self) {
        let icr = self.read_reg(reg::ICR);

        if icr & int::LSC != 0 {
            self.update_link_status();
            if self.link_up {
                crate::log::info!("e1000: Link UP {}Mbps", self.link_speed);
            } else {
                crate::log::info!("e1000: Link DOWN");
            }
        }

        if icr & int::RXT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::RXDMT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::TXDW != 0 {
            self.reclaim_tx();
        }
    }

    pub fn reclaim_tx(&mut self) {
        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();

        for i in 0..TX_DESC_COUNT {
            if self.tx_in_flight[i] {
                // SAFETY: tx_descs points to valid descriptor ring memory
                unsafe {
                    let desc = &*tx_descs.add(i);
                    if desc.is_done() {
                        if desc.has_error() {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            if desc.had_excess_collisions() {
                                crate::log_warn!("e1000: TX excess collisions on descriptor {}", i);
                            }
                            if desc.had_late_collision() {
                                crate::log_warn!("e1000: TX late collision on descriptor {}", i);
                            }
                        }
                        self.tx_in_flight[i] = false;
                    }
                }
            }
        }
    }

    pub fn get_rx_stats(&self) -> (u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.rx_errors.load(Ordering::Relaxed),
        )
    }

    pub fn get_tx_stats(&self) -> (u64, u64, u64) {
        (
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.tx_errors.load(Ordering::Relaxed),
        )
    }
}
