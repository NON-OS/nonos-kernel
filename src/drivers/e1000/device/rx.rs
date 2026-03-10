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
use core::sync::atomic::{fence, Ordering};

use super::core::E1000Device;
use crate::drivers::e1000::constants::{rctl, reg, BUFFER_SIZE, RX_DESC_COUNT};
use crate::drivers::e1000::descriptors::E1000RxDesc;

impl E1000Device {
    pub(super) fn init_rx(&mut self) {
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();
        for i in 0..RX_DESC_COUNT {
            // SAFETY: rx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *rx_descs.add(i);
                desc.buffer_addr = self.rx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.checksum = 0;
                desc.status = 0;
                desc.errors = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::RDBAL, (self.rx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::RDBAH, (self.rx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::RDLEN, (RX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::RDH, 0);
        self.write_reg(reg::RDT, (RX_DESC_COUNT - 1) as u32);

        self.rx_tail = RX_DESC_COUNT - 1;

        for i in 0..128 {
            self.write_reg(reg::MTA + (i * 4), 0);
        }

        let rctl_val = rctl::EN | rctl::UPE | rctl::MPE | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC;
        self.write_reg(reg::RCTL, rctl_val);

        crate::sys::serial::print(b"[E1000] RX desc phys=0x");
        crate::sys::serial::print_hex(self.rx_descs_phys.as_u64());
        crate::sys::serial::print(b" RCTL=0x");
        crate::sys::serial::print_hex(rctl_val as u64);
        crate::sys::serial::println(b"");
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();

        static mut DBG_COUNT: u64 = 0;
        unsafe {
            DBG_COUNT += 1;
            if DBG_COUNT % 100 == 1 {
                let rdh = self.read_reg(reg::RDH);
                let rdt = self.read_reg(reg::RDT);
                let status = self.read_reg(reg::STATUS);
                crate::sys::serial::print(b"[E1000] RDH=");
                crate::sys::serial::print_dec(rdh as u64);
                crate::sys::serial::print(b" RDT=");
                crate::sys::serial::print_dec(rdt as u64);
                crate::sys::serial::print(b" STATUS=0x");
                crate::sys::serial::print_hex(status as u64);
                crate::sys::serial::println(b"");
            }
        }

        loop {
            let desc_idx = (self.rx_tail + 1) % RX_DESC_COUNT;

            fence(Ordering::Acquire);

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

                        crate::sys::serial::print(b"[E1000] RX ");
                        crate::sys::serial::print_dec(len as u64);
                        crate::sys::serial::println(b" bytes");

                        self.rx_packets.fetch_add(1, Ordering::Relaxed);
                        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                }

                desc.reset();

                fence(Ordering::Release);
            }

            self.rx_tail = desc_idx;
            self.write_reg(reg::RDT, self.rx_tail as u32);
        }

        packets
    }

    pub fn get_rx_stats(&self) -> (u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.rx_errors.load(Ordering::Relaxed),
        )
    }
}
