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

use super::super::constants::{desc_status, int, reg, tx_desc};
use super::super::constants::{MAX_MTU, RX_BUFFER_SIZE, RX_DESC_COUNT, TX_DESC_COUNT};
use super::super::descriptors::{Rtl8168RxDesc, Rtl8168TxDesc};
use super::core::Rtl8168Device;

impl Rtl8168Device {
    pub fn update_link_status(&mut self) {
        let status = self.read8(reg::PHY_STATUS);

        self.link_up = (status & 0x02) != 0;

        if self.link_up {
            let speed_bits = status & 0x30;
            self.link_speed = match speed_bits {
                0x00 => 10,
                0x10 => 100,
                0x20 => 1000,
                _ => 0,
            };
            self.full_duplex = (status & 0x01) != 0;
        } else {
            self.link_speed = 0;
            self.full_duplex = false;
        }
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_MTU + 14 {
            return Err("Packet too large");
        }

        let descs = self.tx_descs_virt.as_ptr::<Rtl8168TxDesc>();

        unsafe {
            let desc = &*descs.add(self.tx_index);
            if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                self.reclaim_tx();
                if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                    return Err("TX ring full");
                }
            }
        }

        let buf_virt = self.tx_buffers_virt[self.tx_index];
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_virt.as_mut_ptr(), data.len());
        }

        let is_last_ring = self.tx_index == TX_DESC_COUNT - 1;
        unsafe {
            let desc = &*descs.add(self.tx_index);
            let mut opts1 = (data.len() as u32) & 0xFFFF;
            opts1 |= tx_desc::OWN | tx_desc::FS | tx_desc::LS;
            if is_last_ring {
                opts1 |= tx_desc::EOR;
            }
            desc.opts2.store(0, Ordering::Release);
            desc.opts1.store(opts1, Ordering::Release);
        }

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        self.tx_index = (self.tx_index + 1) % TX_DESC_COUNT;

        self.write8(reg::TPP, 0x40);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let descs = self.rx_descs_virt.as_ptr::<Rtl8168RxDesc>();

        for _ in 0..RX_DESC_COUNT {
            unsafe {
                let desc = &*descs.add(self.rx_index);
                let opts1 = desc.opts1.load(Ordering::Acquire);

                if (opts1 & desc_status::OWN) != 0 {
                    break;
                }

                if (opts1 & 0x00200000) != 0 {
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    let length = (opts1 & 0x3FFF) as usize;
                    if length >= 14 && length <= RX_BUFFER_SIZE {
                        let buf_virt = self.rx_buffers_virt[self.rx_index];
                        let mut packet = alloc::vec![0u8; length];
                        core::ptr::copy_nonoverlapping(
                            buf_virt.as_ptr(),
                            packet.as_mut_ptr(),
                            length,
                        );
                        packets.push(packet);
                        self.rx_packets.fetch_add(1, Ordering::Relaxed);
                        self.rx_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    }
                }

                let is_last = self.rx_index == RX_DESC_COUNT - 1;
                let mut new_opts1 = (RX_BUFFER_SIZE as u32) & 0x3FFF;
                new_opts1 |= desc_status::OWN;
                if is_last {
                    new_opts1 |= desc_status::EOR;
                }
                desc.opts2.store(0, Ordering::Release);
                desc.opts1.store(new_opts1, Ordering::Release);

                self.rx_index = (self.rx_index + 1) % RX_DESC_COUNT;
            }
        }

        packets
    }

    pub fn reclaim_tx(&mut self) {
        let descs = self.tx_descs_virt.as_ptr::<Rtl8168TxDesc>();

        while self.tx_clean != self.tx_index {
            unsafe {
                let desc = &*descs.add(self.tx_clean);
                if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                    break;
                }
                let is_last = self.tx_clean == TX_DESC_COUNT - 1;
                let opts1 = if is_last { tx_desc::EOR } else { 0 };
                desc.opts1.store(opts1, Ordering::Release);
            }
            self.tx_clean = (self.tx_clean + 1) % TX_DESC_COUNT;
        }
    }

    pub fn handle_interrupt(&mut self) {
        let isr = self.read16(reg::ISR);
        self.write16(reg::ISR, isr);

        if (isr & int::LINK_CHG) != 0 {
            self.update_link_status();
        }

        if (isr & (int::TOK | int::TER | int::TDU)) != 0 {
            self.reclaim_tx();
        }

        if (isr & int::TER) != 0 {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
        }

        if (isr & int::RER) != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
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
