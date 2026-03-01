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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use super::super::constants::*;
use super::super::error::WifiError;
use super::super::tx::Ieee80211Header;
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
    pub fn transmit(&mut self, data: &[u8]) -> Result<(), WifiError> {
        self.transmit_to(data, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    pub fn transmit_to(&mut self, data: &[u8], dest_mac: &[u8; 6]) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        if self.tx_queues.is_empty() {
            return Err(WifiError::InvalidState);
        }

        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;
        let seq = self.seq_num.fetch_add(1, Ordering::Relaxed) as u16;

        let header = Ieee80211Header::new_data(
            &bssid,
            &self.mac_address,
            dest_mac,
            seq,
        );

        // SAFETY: Ieee80211Header is repr(C) with 24-byte fixed layout per IEEE 802.11
        let header_bytes: [u8; 24] = unsafe {
            core::mem::transmute(header)
        };

        let frame = if let Some(ref mut ccmp) = self.ccmp_context {
            let encrypted = ccmp.encrypt(&header_bytes, data, 0);

            let mut frame = Vec::with_capacity(header_bytes.len() + encrypted.len());
            frame.extend_from_slice(&header_bytes);
            frame.extend_from_slice(&encrypted);
            frame
        } else {
            let mut frame = Vec::with_capacity(header_bytes.len() + data.len());
            frame.extend_from_slice(&header_bytes);
            frame.extend_from_slice(data);
            frame
        };

        let tx_queue = &mut self.tx_queues[0];
        tx_queue.enqueue(&frame)?;

        self.trans.grab_nic_access()?;
        let write_ptr_reg = TX_QUEUE_WRITE_PTR_BASE + (tx_queue.id() as u32 * 4);
        self.trans
            .regs
            .write32(write_ptr_reg, tx_queue.write_ptr());
        self.trans.release_nic_access();

        Ok(())
    }

    pub(crate) fn transmit_raw(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if self.tx_queues.is_empty() {
            return Err(WifiError::InvalidState);
        }

        let tx_queue = &mut self.tx_queues[0];
        tx_queue.enqueue(frame)?;

        self.trans.grab_nic_access()?;
        let write_ptr_reg = TX_QUEUE_WRITE_PTR_BASE + (tx_queue.id() as u32 * 4);
        self.trans
            .regs
            .write32(write_ptr_reg, tx_queue.write_ptr());
        self.trans.release_nic_access();

        Ok(())
    }

    pub(crate) fn send_eapol_frame(&mut self, eapol: &[u8]) -> Result<(), WifiError> {
        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;

        let mut frame = Vec::with_capacity(24 + 8 + eapol.len());

        frame.extend_from_slice(&[0x08, 0x01]);

        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(&bssid);

        frame.extend_from_slice(&self.mac_address);

        frame.extend_from_slice(&bssid);

        let seq = self.seq_num.fetch_add(1, Ordering::Relaxed) as u16;
        frame.extend_from_slice(&((seq << 4) as u16).to_le_bytes());

        frame.extend_from_slice(&[0xAA, 0xAA, 0x03]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x88, 0x8E]);

        frame.extend_from_slice(eapol);

        self.transmit_raw(&frame)
    }
}
