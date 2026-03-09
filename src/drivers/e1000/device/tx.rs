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

use core::sync::atomic::Ordering;

use super::core::E1000Device;
use crate::drivers::e1000::constants::{
    reg, tctl, tx_cmd, BUFFER_SIZE, DEFAULT_COLLISION_DISTANCE, DEFAULT_COLLISION_THRESHOLD,
    DEFAULT_TIPG, MIN_FRAME_SIZE, TX_DESC_COUNT,
};
use crate::drivers::e1000::descriptors::E1000TxDesc;

impl E1000Device {
    pub(super) fn init_tx(&mut self) {
        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();
        for i in 0..TX_DESC_COUNT {
            // SAFETY: tx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *tx_descs.add(i);
                desc.buffer_addr = self.tx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.cso = 0;
                desc.cmd = 0;
                desc.status = 1;
                desc.css = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::TDBAL, (self.tx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::TDBAH, (self.tx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::TDLEN, (TX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::TDH, 0);
        self.write_reg(reg::TDT, 0);

        self.tx_tail = 0;

        self.write_reg(reg::TIPG, DEFAULT_TIPG);

        let tctl_val = tctl::EN
            | tctl::PSP
            | (DEFAULT_COLLISION_THRESHOLD << tctl::CT_SHIFT)
            | (DEFAULT_COLLISION_DISTANCE << tctl::COLD_SHIFT)
            | tctl::RTLC;
        self.write_reg(reg::TCTL, tctl_val);
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

    pub fn get_tx_stats(&self) -> (u64, u64, u64) {
        (
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.tx_errors.load(Ordering::Relaxed),
        )
    }
}
