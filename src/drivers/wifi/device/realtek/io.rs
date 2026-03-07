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

/*
DMA ring buffer I/O for Realtek WiFi. Handles packet reception from RX ring,
transmission via TX ring, and raw frame transmission for management frames.
Descriptor ownership managed via OWN bit for hardware/software handoff.
*/

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;

use super::super::super::error::WifiError;
use super::super::types::WifiState;
use super::constants::*;
use super::core::RealtekWifiDevice;
use super::descriptors::{RtlTxDesc, RtlRxDesc};

impl RealtekWifiDevice {
    pub(crate) fn transmit_raw(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if frame.len() > TX_BUFFER_SIZE - 48 {
            return Err(WifiError::BufferTooSmall);
        }

        let desc_ptr = (self.tx_ring_virt.as_u64() + (self.tx_head * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Err(WifiError::HardwareError);
        }

        let buf_addr = self.tx_buffers_virt.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), (buf_addr + 48) as *mut u8, frame.len());
        }

        let buf_phys = self.tx_buffers_phys.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        desc.configure_tx((frame.len() + 48) as u16, buf_phys);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<Vec<u8>>, WifiError> {
        let desc_ptr = (self.rx_ring_virt.as_u64() + (self.rx_head * core::mem::size_of::<RtlRxDesc>()) as u64) as *const RtlRxDesc;
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Ok(None);
        }

        if desc.is_crc_err() || desc.is_icv_err() {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let pkt_len = desc.pkt_len() as usize;
        if pkt_len == 0 || pkt_len > RX_BUFFER_SIZE {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let buf_addr = self.rx_buffers_virt.as_u64() + (self.rx_head * RX_BUFFER_SIZE) as u64;
        let mut data = alloc::vec![0u8; pkt_len];

        unsafe {
            ptr::copy_nonoverlapping(buf_addr as *const u8, data.as_mut_ptr(), pkt_len);
        }

        desc.set_own();
        self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;

        Ok(Some(data))
    }

    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        if frame.len() > TX_BUFFER_SIZE - 48 {
            return Err(WifiError::BufferTooSmall);
        }

        let desc_ptr = (self.tx_ring_virt.as_u64() + (self.tx_head * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Err(WifiError::HardwareError);
        }

        let buf_addr = self.tx_buffers_virt.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;

        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), (buf_addr + 48) as *mut u8, frame.len());
        }

        let buf_phys = self.tx_buffers_phys.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        desc.configure_tx((frame.len() + 48) as u16, buf_phys);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;

        Ok(())
    }

    pub fn process_rx_ring(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        loop {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (self.rx_head * core::mem::size_of::<RtlRxDesc>()) as u64) as *const RtlRxDesc;
            let desc = unsafe { &*desc_ptr };

            if desc.is_own() {
                break;
            }

            if desc.is_crc_err() || desc.is_icv_err() {
                desc.clear_own();
                desc.set_own();
                self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
                continue;
            }

            if !desc.is_first_seg() || !desc.is_last_seg() {
                desc.set_own();
                self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
                continue;
            }

            let pkt_len = desc.pkt_len() as usize;
            if pkt_len > 0 && pkt_len <= RX_BUFFER_SIZE {
                let buf_addr = self.rx_buffers_virt.as_u64() + (self.rx_head * RX_BUFFER_SIZE) as u64;
                let mut data = alloc::vec![0u8; pkt_len];
                unsafe {
                    ptr::copy_nonoverlapping(buf_addr as *const u8, data.as_mut_ptr(), pkt_len);
                }
                frames.push(data);
            }

            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
        }

        frames
    }

    pub fn init_tx_descriptors(&mut self) {
        for i in 0..TX_RING_SIZE {
            let desc_ptr = (self.tx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;
            unsafe {
                ptr::write(desc_ptr, RtlTxDesc::new());
            }
        }
    }

    pub fn init_rx_descriptors(&mut self) {
        for i in 0..RX_RING_SIZE {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlRxDesc>()) as u64) as *mut RtlRxDesc;
            let buf_addr = self.rx_buffers_phys.as_u64() + (i * RX_BUFFER_SIZE) as u64;
            unsafe {
                ptr::write(desc_ptr, RtlRxDesc::new());
                let desc = &*desc_ptr;
                desc.configure_rx(RX_BUFFER_SIZE as u16, buf_addr);
            }
        }
    }
}
