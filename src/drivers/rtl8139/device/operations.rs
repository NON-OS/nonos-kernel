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
use super::super::io::{inb, inl, outl, outw};
use super::core::Rtl8139Device;

impl Rtl8139Device {
    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > TX_BUFFER_SIZE {
            return Err("Packet too large");
        }
        if data.len() < MIN_FRAME_SIZE {
            return Err("Packet too small");
        }

        let desc = self.tx_cur;
        let tsd_reg = match desc {
            0 => reg::TSD0,
            1 => reg::TSD1,
            2 => reg::TSD2,
            3 => reg::TSD3,
            _ => return Err("Invalid TX descriptor"),
        };

        let tsd_val = inl(self.io_base + tsd_reg);
        if tsd_val & tsd::OWN != 0 {
            return Err("TX descriptor busy");
        }

        // SAFETY: tx_buffers_virt[desc] points to valid DMA memory of TX_BUFFER_SIZE bytes
        unsafe {
            let buf_ptr = self.tx_buffers_virt[desc].as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());
        }

        let new_tsd = (data.len() as u32) & 0x1FFF;
        outl(self.io_base + tsd_reg, new_tsd);

        self.tx_cur = (self.tx_cur + 1) % TX_DESC_COUNT;

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        let cr = inb(self.io_base + reg::CR);
        if cr & cmd::BUFE != 0 {
            return packets;
        }

        let rx_buf = self.rx_buffer_virt.as_ptr::<u8>();

        loop {
            let header_offset = self.rx_offset as usize;

            if header_offset >= RX_BUFFER_SIZE - 4 {
                break;
            }

            // SAFETY: rx_buf points to valid DMA memory, header_offset is bounds-checked
            unsafe {
                let header = core::ptr::read_volatile(rx_buf.add(header_offset) as *const u32);
                let status = (header & 0xFFFF) as u16;
                let length = ((header >> 16) & 0xFFFF) as u16;

                if status & 0x0001 == 0 {
                    if status == 0 {
                        break;
                    }
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                    self.rx_offset = (self.rx_offset + length + 4 + 3) & !3;
                    continue;
                }

                if length < 8 || length > 1518 + 4 {
                    break;
                }

                let data_offset = (header_offset + 4) % (RX_BUFFER_SIZE - 16);
                let data_len = (length - 4) as usize;

                let mut packet = Vec::with_capacity(data_len);
                packet.set_len(data_len);

                let first_part = (RX_BUFFER_SIZE - 16 - data_offset).min(data_len);
                core::ptr::copy_nonoverlapping(
                    rx_buf.add(data_offset),
                    packet.as_mut_ptr(),
                    first_part,
                );

                if first_part < data_len {
                    core::ptr::copy_nonoverlapping(
                        rx_buf,
                        packet.as_mut_ptr().add(first_part),
                        data_len - first_part,
                    );
                }

                packets.push(packet);

                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(data_len as u64, Ordering::Relaxed);

                self.rx_offset =
                    ((self.rx_offset + length + 4 + 3) & !3) % (RX_BUFFER_SIZE as u16 - 16);

                outw(self.io_base + reg::CAPR, self.rx_offset.wrapping_sub(0x10));
            }

            if packets.len() >= 32 {
                break;
            }
        }

        packets
    }
}
